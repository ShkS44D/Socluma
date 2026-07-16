import pytest

from src.services.llm_provider import llm_provider


@pytest.fixture(autouse=True)
def disable_live_openai_for_automated_tests(monkeypatch):
    """Normal automated tests must never consume OpenAI API credits."""

    monkeypatch.setattr(llm_provider, "client", None)

