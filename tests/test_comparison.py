VULNERABLE_CODE = """
import os
DB_PASSWORD = "super_secret_123"
result = eval(user_input)
def connect():
    return os.getenv("DB_URL")
"""

LLM_SELECTION = ["mock:mock-model"]  # matches MockLLMAnalyzer.provider:model


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
    token = _get_dev_token(client)
    response = client.post(
        "/submissions/",
        json={"code": VULNERABLE_CODE, "language": "python",
              "selected_llms": LLM_SELECTION},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 201
    body = response.json()
    assert len(body["analyses"]) == 2
    analyzer_types = {a["analyzer_type"] for a in body["analyses"]}
    assert "semgrep" in analyzer_types
    assert "llm" in analyzer_types


def test_both_analyzers_find_hardcoded_password(client):
    token = _get_dev_token(client)
    response = client.post(
        "/submissions/",
        json={"code": VULNERABLE_CODE, "language": "python",
              "selected_llms": LLM_SELECTION},
        headers={"Authorization": f"Bearer {token}"},
    )
    body = response.json()
    for analysis in body["analyses"]:
        assert analysis["status"] == "completed"
        password_findings = [
            f for f in analysis["findings"]
            if "password" in f["message"].lower() or "secret" in f["message"].lower()
        ]
        assert len(password_findings) >= 1, (
            f"{analysis['analyzer_type']} did not detect the hardcoded password"
        )


def test_llm_finds_eval_that_semgrep_misses(client):
    token = _get_dev_token(client)
    response = client.post(
        "/submissions/",
        json={"code": VULNERABLE_CODE, "language": "python",
              "selected_llms": LLM_SELECTION},
        headers={"Authorization": f"Bearer {token}"},
    )
    body = response.json()
    llm_analysis = next(
        (a for a in body["analyses"] if a["analyzer_type"] == "llm"), None
    )
    assert llm_analysis is not None, "No LLM analysis found"
    eval_findings = [
        f for f in llm_analysis["findings"]
        if "eval" in f["rule_id"] or "eval" in f["message"].lower()
    ]
    assert len(eval_findings) >= 1


def test_explanation_toggle_on(client):
    token = _get_dev_token(client)
    response = client.post(
        "/submissions/",
        json={"code": VULNERABLE_CODE, "language": "python",
              "selected_llms": LLM_SELECTION, "explanation_enabled": True},
        headers={"Authorization": f"Bearer {token}"},
    )
    body = response.json()
    llm_analysis = next(
        (a for a in body["analyses"] if a["analyzer_type"] == "llm"), None
    )
    assert llm_analysis is not None
    for finding in llm_analysis["findings"]:
        assert finding["explanation"] is not None


def test_explanation_toggle_off(client):
    token = _get_dev_token(client)
    response = client.post(
        "/submissions/",
        json={"code": VULNERABLE_CODE, "language": "python",
              "selected_llms": LLM_SELECTION, "explanation_enabled": False},
        headers={"Authorization": f"Bearer {token}"},
    )
    body = response.json()
    llm_analysis = next(
        (a for a in body["analyses"] if a["analyzer_type"] == "llm"), None
    )
    assert llm_analysis is not None
    for finding in llm_analysis["findings"]:
        assert finding["explanation"] is None


def test_without_selected_llms_only_sast_runs(client):
    token = _get_dev_token(client)
    response = client.post(
        "/submissions/",
        json={"code": VULNERABLE_CODE, "language": "python"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 201
    body = response.json()
    analyzer_types = {a["analyzer_type"] for a in body["analyses"]}
    assert "llm" not in analyzer_types
    assert len(body["analyses"]) >= 1