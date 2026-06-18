def test_register_returns_user_without_password(client):
    response = client.post(
        "/auth/register",
        json={"email": "alice@example.com", "password": "alice12345"},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["email"] == "alice@example.com"
    assert body["role"] == "developer"
    assert "password" not in body  # nessuna leak della password
    assert "password_hash" not in body


def test_register_duplicate_email_returns_409(client):
    client.post(
        "/auth/register",
        json={"email": "bob@example.com", "password": "bob123456"},
    )
    response = client.post(
        "/auth/register",
        json={"email": "bob@example.com", "password": "anotherpw"},
    )
    assert response.status_code == 409


def test_login_with_valid_credentials_returns_tokens(client):
    client.post(
        "/auth/register",
        json={"email": "carol@example.com", "password": "carol12345"},
    )
    response = client.post(
        "/auth/login",
        json={"email": "carol@example.com", "password": "carol12345"},
    )
    assert response.status_code == 200
    body = response.json()
    assert "access_token" in body
    assert "refresh_token" in body
    assert body["token_type"] == "bearer"


def test_login_with_wrong_password_returns_401(client):
    client.post(
        "/auth/register",
        json={"email": "dave@example.com", "password": "dave12345"},
    )
    response = client.post(
        "/auth/login",
        json={"email": "dave@example.com", "password": "WRONG"},
    )
    assert response.status_code == 401


def test_login_with_unknown_email_returns_401(client):
    response = client.post(
        "/auth/login",
        json={"email": "ghost@example.com", "password": "anypassword"},
    )
    assert response.status_code == 401

def test_me_without_token_returns_401(client):
    response = client.get("/auth/me")
    assert response.status_code == 401


def test_me_with_valid_token_returns_user(client):
    # Register
    client.post(
        "/auth/register",
        json={"email": "eve@example.com", "password": "eve1234567"},
    )
    # Login
    login_resp = client.post(
        "/auth/login",
        json={"email": "eve@example.com", "password": "eve1234567"},
    )
    token = login_resp.json()["access_token"]

    # Me
    response = client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["email"] == "eve@example.com"
    assert body["role"] == "developer"
    assert "password" not in body
    assert "password_hash" not in body


def test_me_with_invalid_token_returns_401(client):
    response = client.get(
        "/auth/me",
        headers={"Authorization": "Bearer not.a.real.token"},
    )
    assert response.status_code == 401