VULNERABLE_CODE = """
import os
DB_PASSWORD = "super_secret_123"
def connect():
    return os.getenv("DB_URL")
"""

CLEAN_CODE = """
import os
def connect():
    return os.getenv("DB_URL")
"""


def _get_dev_token(client):
    """Helper: register a developer and return their access token."""
    client.post(
        "/auth/register",
        json={"email": "dev@example.com", "password": "devpassword"},
    )
    resp = client.post(
        "/auth/login",
        json={"email": "dev@example.com", "password": "devpassword"},
    )
    return resp.json()["access_token"]


def test_submit_vulnerable_code_returns_findings(client):
    token = _get_dev_token(client)
    response = client.post(
        "/submissions/",
        json={"code": VULNERABLE_CODE, "language": "python"},
        headers={"Authorization": f"Bearer {token}"},
    )
    print(response.json())
    assert response.status_code == 201
    body = response.json()
    assert len(body["analyses"]) >= 1

    analysis = body["analyses"][0]
    assert analysis["status"] == "completed"
    assert analysis["findings_count"] >= 1
    assert analysis["findings"][0]["severity"] == "high"
    assert analysis["findings"][0]["rule_id"] == "mock-hardcoded-password"
    assert analysis["findings"][0]["status"] == "unreviewed"


def test_submit_clean_code_returns_no_findings(client):
    token = _get_dev_token(client)
    response = client.post(
        "/submissions/",
        json={"code": CLEAN_CODE, "language": "python"},
        headers={"Authorization": f"Bearer {token}"},
    )
    print(response.json())
    assert response.status_code == 201
    body = response.json()
    analysis = body["analyses"][0]
    assert analysis["findings_count"] == 0


def test_unauthenticated_cannot_submit(client):
    response = client.post(
        "/submissions/",
        json={"code": "print('hello')", "language": "python"},
    )
    assert response.status_code == 401


def test_admin_cannot_submit(client, admin_token):
    """Only developers can submit code, not admins."""
    response = client.post(
        "/submissions/",
        json={"code": "x = 1", "language": "python"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 403


def test_list_submissions_returns_user_history(client):
    token = _get_dev_token(client)
    client.post(
        "/submissions/",
        json={"code": "x = 1", "language": "python"},
        headers={"Authorization": f"Bearer {token}"},
    )
    client.post(
        "/submissions/",
        json={"code": "y = 2", "language": "python"},
        headers={"Authorization": f"Bearer {token}"},
    )

    response = client.get(
        "/submissions/",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert len(response.json()) == 2


def test_get_submission_by_id(client):
    token = _get_dev_token(client)
    create_resp = client.post(
        "/submissions/",
        json={"code": VULNERABLE_CODE, "language": "python"},
        headers={"Authorization": f"Bearer {token}"},
    )
    print(create_resp)
    submission_id = create_resp.json()["id"]

    response = client.get(
        f"/submissions/{submission_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["id"] == submission_id
    assert len(body["analyses"]) >= 1


def test_get_nonexistent_submission_returns_404(client):
    token = _get_dev_token(client)
    response = client.get(
        "/submissions/00000000-0000-0000-0000-000000000000",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 404