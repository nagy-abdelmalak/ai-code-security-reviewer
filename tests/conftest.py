import pytest 
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine
from sqlmodel.pool import StaticPool

from app.db.session import get_session
from app.main import app
from app.core.security import hash_password
from app.models import Role, User

@pytest.fixture(name="session")
def session_fixture():
    """An in-memory SQLite DB session, isolated per test"""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session

@pytest.fixture(name = "client")
def client_fixture(session: Session):
    """A FastAPI TestClient with the DB dependency overridden to use the test session"""
    def get_session_override():
        return session
    
    app.dependency_overrides[get_session] = get_session_override
    client = TestClient(app)
    yield client
    app.dependency_overrides.clear()

@pytest.fixture(name="admin_token")
def admin_token_fixture(client, session):
    """Create a bootstrap admin in the test DB and return their access token."""
    admin = User(
        email="admin@example.com",
        password_hash=hash_password("change-this-immediately"),
        role=Role.ADMIN,
    )
    session.add(admin)
    session.commit()

    resp = client.post(
        "/auth/login",
        json={"email": "admin@example.com", "password": "change-this-immediately"},
    )
    return resp.json()["access_token"]