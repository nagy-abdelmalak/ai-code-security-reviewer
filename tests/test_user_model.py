import pytest
from sqlmodel import Session, select

from app.models.user import Role, User

def test_create_user_defaults(session: Session):
    user = User(email="marco@example.com", password_hash="fake_hash")
    session.add(user)
    session.commit()
    session.refresh(user)

    assert user.id is not None
    assert user.is_active is True
    assert user.email == "marco@example.com"
    assert user.password_hash == "fake_hash"
    assert user.created_at is not None

def test_email_must_be_unique(session: Session):
    user1 = User(email="marco1@example.com", password_hash="fake_hash1")
    user2 = User(email="marco1@example.com", password_hash="fake_hash2")

    session.add(user1)
    session.commit()

    session.add(user2)
    with pytest.raises(Exception):
        session.commit()

def test_query_user_by_email(session: Session):
    user = User(email="marco@example.com", password_hash="fake_hash")
    session.add(user)
    session.commit()
    session.refresh(user)

    found = session.exec(
        select(User).where(User.email=="marco@example.com")
    ).first()

    assert found is not None
    assert found.email == "marco@example.com"

def test_role_enum_seriliaztion(session: Session):
    admin = User(
        email="admin@example.com",
        password_hash= "fask_hash3",
        role=Role.ADMIN
    )
    session.add(admin)
    session.commit()
    session.refresh(admin)

    assert admin.role == Role.ADMIN
    assert admin.role.value == "admin"