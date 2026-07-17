import json
import unittest
from types import SimpleNamespace

import httpx
import openai

from src.services.llm_provider import CopilotStructuredOutput, OpenAIProvider


class FakeResponses:
    def __init__(self, response=None, error=None):
        self.response = response
        self.error = error
        self.kwargs = None

    def parse(self, **kwargs):
        self.kwargs = kwargs
        if self.error:
            raise self.error
        return self.response


class FakeClient:
    def __init__(self, responses):
        self.responses = responses


def settings():
    return SimpleNamespace(
        OPENAI_API_KEY="configured-for-test",
        OPENAI_MODEL="gpt-5.6-luna",
        OPENAI_TIMEOUT_SECONDS=60,
        OPENAI_MAX_OUTPUT_TOKENS=2000,
        OPENAI_REASONING_EFFORT="medium",
    )


def response(*, parsed=None, status="completed", output=None):
    return SimpleNamespace(
        status=status,
        model="gpt-5.6-luna-2026-07-01",
        id="resp_123",
        _request_id="req_123",
        output=output or [],
        output_parsed=parsed,
        incomplete_details=SimpleNamespace(reason="max_output_tokens") if status == "incomplete" else None,
        usage=SimpleNamespace(
            input_tokens=120,
            output_tokens=45,
            total_tokens=165,
            input_tokens_details=SimpleNamespace(cached_tokens=20),
            output_tokens_details=SimpleNamespace(reasoning_tokens=15),
        ),
    )


class OpenAIProviderTests(unittest.TestCase):
    def provider(self, fake_responses):
        provider = OpenAIProvider(client=FakeClient(fake_responses))
        provider.settings = settings()
        return provider

    def valid_output(self):
        return CopilotStructuredOutput(
            answer="Grounded answer.",
            evidence_references=[{"type": "incident", "id": "incident-1"}],
            confidence=88,
            limitations=["Endpoint telemetry is incomplete."],
            suggested_follow_up_questions=["Which endpoint should be checked next?"],
        )

    def test_success_uses_responses_parse_and_captures_usage(self):
        fake = FakeResponses(response(parsed=self.valid_output()))
        result = self.provider(fake).generate_copilot("bounded context", "trusted instructions")

        self.assertTrue(result.succeeded)
        self.assertEqual(fake.kwargs["model"], "gpt-5.6-luna")
        self.assertEqual(fake.kwargs["reasoning"], {"effort": "medium"})
        self.assertEqual(fake.kwargs["max_output_tokens"], 2000)
        self.assertEqual(fake.kwargs["timeout"], 60.0)
        self.assertFalse(fake.kwargs["store"])
        self.assertEqual(fake.kwargs["tools"], [])
        self.assertIs(fake.kwargs["text_format"], CopilotStructuredOutput)
        self.assertEqual(result.metadata["resolved_model"], "gpt-5.6-luna-2026-07-01")
        self.assertEqual(result.metadata["response_id"], "resp_123")
        self.assertEqual(result.metadata["request_id"], "req_123")
        self.assertEqual(result.metadata["cached_input_tokens"], 20)
        self.assertEqual(result.metadata["reasoning_tokens"], 15)

    def test_missing_key_activates_fallback_without_call(self):
        fake = FakeResponses(response(parsed=self.valid_output()))
        provider = self.provider(fake)
        provider.client = None
        result = provider.generate_copilot("bounded context", "trusted instructions")
        self.assertEqual(result.error_category, "missing_api_key")
        self.assertIsNone(fake.kwargs)

    def test_incomplete_refusal_empty_and_malformed_are_classified(self):
        incomplete = self.provider(FakeResponses(response(status="incomplete"))).generate_copilot("x", "y")
        self.assertEqual(incomplete.error_category, "incomplete_response")

        refusal_item = SimpleNamespace(content=[SimpleNamespace(type="refusal", refusal="not allowed")])
        refused = self.provider(FakeResponses(response(parsed=None, output=[refusal_item]))).generate_copilot("x", "y")
        self.assertEqual(refused.error_category, "content_refusal")

        malformed = self.provider(FakeResponses(response(parsed=None))).generate_copilot("x", "y")
        self.assertEqual(malformed.error_category, "structured_output_error")

        empty = self.provider(FakeResponses(response(parsed={
            "answer": " ", "evidence_references": [], "confidence": 1,
            "limitations": [], "suggested_follow_up_questions": [],
        }))).generate_copilot("x", "y")
        self.assertEqual(empty.error_category, "empty_response")

    def test_openai_error_classification(self):
        request = httpx.Request("POST", "https://api.openai.com/v1/responses")

        def status_error(cls, status, body):
            return cls(
                "safe test error",
                response=httpx.Response(status, request=request),
                body=body,
            )

        cases = [
            (openai.AuthenticationError, 401, {}, "invalid_api_key"),
            (openai.PermissionDeniedError, 403, {}, "permission_denied"),
            (openai.NotFoundError, 404, {}, "model_not_found"),
            (openai.RateLimitError, 429, {"error": {"code": "rate_limit_exceeded"}}, "rate_limited"),
            (openai.RateLimitError, 429, {"error": {"code": "insufficient_quota"}}, "insufficient_quota"),
        ]
        for cls, status, body, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(OpenAIProvider._classify_error(status_error(cls, status, body)), expected)
        self.assertEqual(OpenAIProvider._classify_error(openai.APITimeoutError(request)), "timeout")
        self.assertEqual(
            OpenAIProvider._classify_error(openai.APIConnectionError(request=request)),
            "connection_error",
        )
        self.assertEqual(
            OpenAIProvider._classify_error(json.JSONDecodeError("bad", "x", 0)),
            "malformed_response",
        )


if __name__ == "__main__":
    unittest.main()
