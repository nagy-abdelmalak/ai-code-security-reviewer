import json

VULNERABLE_CODE = """
import os
DB_PASSWORD = "super_secret_123"
"""

def _get_dev_token(client):
    client.post(
        "/auth/register",
        json={"email": "exporter@example.com", "password": "exportpassword"},
    )
    resp = client.post(
        "/auth/login",
        json={"email": "exporter@example.com", "password": "exportpassword"},
    )
    return resp.json()["access_token"]


def test_export_submission_as_json(client):
    token = _get_dev_token(client)

    # Create a submission
    create_resp = client.post(
        "/submissions/",
        json={"code": VULNERABLE_CODE, "language": "python"},
        headers={"Authorization": f"Bearer {token}"},
    )
    submission_id = create_resp.json()["id"]

    # Export
    response = client.get(
        f"/export/{submission_id}/json",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    assert "attachment" in response.headers.get("content-disposition", "")

    data = response.json()
    assert "submission" in data
    assert "analyses" in data
    assert "metadata" in data
    assert data["submission"]["id"] == submission_id
    assert data["metadata"]["export_format"] == "json"


def test_export_nonexistent_submission_returns_404(client):
    token = _get_dev_token(client)
    response = client.get(
        "/export/00000000-0000-0000-0000-000000000000/json",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 404


def test_unauthenticated_cannot_export(client):
    response = client.get("/export/00000000-0000-0000-0000-000000000000/json")
    assert response.status_code == 401