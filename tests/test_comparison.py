"""
Tests for the side-by-side comparison (User Story #3).

This is the thesis-critical test: verifies that the same code produces
findings from BOTH analyzers (Semgrep and LLM) and that results are
returned together for comparison.
"""

VULNERABLE_CODE = """
import os
DB_PASSWORD = "super_secret_123"
result = eval(user_input)
def connect():
    return os.getenv("DB_URL")
"""


def _get_dev_token(client):
    client.post(
        "/auth/register",
        json={"email": "researcher@example.com", "password": "researcher123"},
    )
    resp = client.post(
        "/auth/login",
        json={"email": "researcher@example.com", "password": "researcher123"},
    )
    return resp.json()["access_token"]


def test_side_by_side_returns_two_analyses(client):
    """Both Semgrep and LLM analyses are returned for the same submission."""
    token = _get_dev_token(client)
    response = client.post(
        "/submissions/",
        json={
            "code": VULNERABLE_CODE,
            "language": "python",
            "run_llm": True,
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 201
    body = response.json()

    # Must have exactly 2 analyses
    assert len(body["analyses"]) == 2

    analyzer_types = {a["analyzer_type"] for a in body["analyses"]}
    assert "semgrep" in analyzer_types
    assert "llm" in analyzer_types


def test_both_analyzers_find_hardcoded_password(client):
    """Both Semgrep and LLM should flag the hardcoded password."""
    token = _get_dev_token(client)
    response = client.post(
        "/submissions/",
        json={
            "code": VULNERABLE_CODE,
            "language": "python",
            "run_llm": True,
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    body = response.json()

    for analysis in body["analyses"]:
        assert analysis["status"] == "completed"
        assert analysis["findings_count"] >= 1

        # At least one finding should be about the password
        password_findings = [
            f for f in analysis["findings"]
            if "password" in f["message"].lower() or "secret" in f["message"].lower()
        ]
        assert len(password_findings) >= 1, (
            f"{analysis['analyzer_type']} did not detect the hardcoded password"
        )


def test_llm_finds_eval_that_semgrep_misses(client):
    """LLM can detect eval() usage — demonstrates LLM contextual understanding."""
    token = _get_dev_token(client)
    response = client.post(
        "/submissions/",
        json={
            "code": VULNERABLE_CODE,
            "language": "python",
            "run_llm": True,
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    body = response.json()

    llm_analysis = next(a for a in body["analyses"] if a["analyzer_type"] == "llm")
    eval_findings = [
        f for f in llm_analysis["findings"]
        if "eval" in f["rule_id"] or "eval" in f["message"].lower()
    ]
    assert len(eval_findings) >= 1


def test_explanation_toggle_on(client):
    """When explanation_enabled=True, LLM findings include explanations."""
    token = _get_dev_token(client)
    response = client.post(
        "/submissions/",
        json={
            "code": VULNERABLE_CODE,
            "language": "python",
            "run_llm": True,
            "explanation_enabled": True,
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    body = response.json()
    llm_analysis = next(a for a in body["analyses"] if a["analyzer_type"] == "llm")

    for finding in llm_analysis["findings"]:
        assert finding["explanation"] is not None
        assert len(finding["explanation"]) > 10


def test_explanation_toggle_off(client):
    """When explanation_enabled=False, explanations are None."""
    token = _get_dev_token(client)
    response = client.post(
        "/submissions/",
        json={
            "code": VULNERABLE_CODE,
            "language": "python",
            "run_llm": True,
            "explanation_enabled": False,
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    body = response.json()
    llm_analysis = next(a for a in body["analyses"] if a["analyzer_type"] == "llm")

    for finding in llm_analysis["findings"]:
        assert finding["explanation"] is None


def test_without_run_llm_only_semgrep(client):
    """When run_llm=False, only Semgrep analysis is returned."""
    token = _get_dev_token(client)
    response = client.post(
        "/submissions/",
        json={
            "code": VULNERABLE_CODE,
            "language": "python",
            "run_llm": False,
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    body = response.json()

    assert len(body["analyses"]) == 1
    assert body["analyses"][0]["analyzer_type"] == "semgrep"