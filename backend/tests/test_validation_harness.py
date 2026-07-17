from pathlib import Path


def test_performance_idempotency_uses_active_copilot_provider_boundary():
    script = (
        Path(__file__).resolve().parents[1]
        / "scripts"
        / "incident_performance_validation.py"
    ).read_text(encoding="utf-8")
    function = script.split("def verify_copilot_idempotency(", 1)[1].split(
        "\ndef _run_with_engine(", 1
    )[0]

    assert "llm_provider.generate_copilot" in function
    assert "llm_provider.generate_text" not in function
