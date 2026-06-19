def _register_and_login(client, email, password):
    """Helper: register a user and return their access token."""
    client.post("/auth/register", json={"email": email, "password": password})
    resp = client.post("/auth/login", json={"email": email, "password": password})
    return resp.json()["access_token"]


def test_admin_can_list_users(client, admin_token):
    response = client.get(
        "/admin/",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_developer_cannot_list_users(client):
    dev_tok = _register_and_login(client, "dev1@example.com", "dev1password")
    response = client.get(
        "/admin/",
        headers={"Authorization": f"Bearer {dev_tok}"},
    )
    assert response.status_code == 403


def test_admin_can_change_role(client, admin_token):
    dev_tok = _register_and_login(client, "dev2@example.com", "dev2password")
    me_resp = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {dev_tok}"},
    )
    dev_id = me_resp.json()["id"]

    response = client.put(
        f"/admin/{dev_id}/role",
        json={"role": "auditor"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    assert response.json()["role"] == "auditor"


def test_developer_cannot_change_role(client):
    dev_tok = _register_and_login(client, "dev3@example.com", "dev3password")
    me_resp = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {dev_tok}"},
    )
    dev_id = me_resp.json()["id"]

    response = client.put(
        f"/admin/{dev_id}/role",
        json={"role": "admin"},
        headers={"Authorization": f"Bearer {dev_tok}"},
    )
    assert response.status_code == 403