import os
os.environ["JWT_SECRET_KEY"] = "test-secret-for-pytest"
os.environ["INITIAL_ADMIN_EMAIL"] = "admin@test.local"
os.environ["INITIAL_ADMIN_PASSWORD"] = "test-password"
os.environ["DATABASE_URL"] = "sqlite:///./test.db"
os.environ["ENVIRONMENT"] = "test"

import pytest
from fastapi import Depends
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine
from sqlmodel.pool import StaticPool

from app.analyzers.port import AnalysisResult, AnalyzerFinding, AnalysisStatus
from app.core.security import hash_password
from app.db.session import get_session
from app.main import app
from app.models.analysis import AnalyzerType
from app.models.finding import Severity
from app.models.user import Role, User
from app.services.analysis_service import (
    AnalysisService,
    AnalysisOrchestrator,
    SubmissionRepository,
)

class MockLLMAnalyzer:
    """Fake LLM analyzer for testing without real API calls."""

    @property
    def name(self) -> str:
        return "llm"

    @property
    def type(self) -> AnalyzerType:
        return AnalyzerType.LLM

    @property
    def version(self) -> str:
        return "mock-v1"

    async def analyze(
        self, code: str, language: str, explanation_enabled: bool = True
    ) -> AnalysisResult:
        findings = []
        for i, line in enumerate(code.splitlines(), start=1):
            if "password" in line.lower() and "=" in line:
                findings.append(
                    AnalyzerFinding(
                        severity=Severity.HIGH,
                        line_number=i,
                        rule_id="llm-hardcoded-secret",
                        message="LLM detected a hardcoded secret",
                        explanation=(
                            "Hardcoded secrets can be extracted from source code."
                            if explanation_enabled
                            else None
                        ),
                    )
                )
            if "eval(" in line:
                findings.append(
                    AnalyzerFinding(
                        severity=Severity.HIGH,
                        line_number=i,
                        rule_id="llm-code-injection",
                        message="Use of eval() allows arbitrary code execution",
                        explanation=(
                            "eval() executes any string as code, enabling injection."
                            if explanation_enabled
                            else None
                        ),
                    )
                )
        return AnalysisResult(
            status=AnalysisStatus.COMPLETED,
            findings=findings,
            duration_ms=50,
        )

class MockSemgrepAnalyzer:
    """Fake semgrep analyzer for testing without real semgrep installed."""

    @property
    def name(self) -> str:
        return "semgrep"

    @property
    def type(self) -> AnalyzerType:
        return AnalyzerType.SEMGREP

    @property
    def version(self) -> str:
        return "mock"

    async def analyze(
        self, code: str, language: str, explanation_enabled: bool = False
    ) -> AnalysisResult:
        findings = []
        for i, line in enumerate(code.splitlines(), start=1):
            if "password" in line.lower() and "=" in line:
                findings.append(
                    AnalyzerFinding(
                        severity=Severity.HIGH,
                        line_number=i,
                        rule_id="mock-hardcoded-password",
                        message="Possible hardcoded password detected",
                    )
                )
        return AnalysisResult(
            status=AnalysisStatus.COMPLETED,
            findings=findings,
            duration_ms=10,
        )


@pytest.fixture(name="session")
def session_fixture():
    """An in-memory SQLite DB session, isolated per test."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SQLModel.metadata.create_all(engine)
    with Session(engine) as session:
        yield session


@pytest.fixture(name="client")
def client_fixture(session: Session):
    def get_session_override():
        return session

    app.dependency_overrides[get_session] = get_session_override

    try:
        from app.api.deps import get_analysis_service

        def get_mock_service(session: Session = Depends(get_session)):
            repo = SubmissionRepository(session)
            orchestrator = AnalysisOrchestrator(
                analyzers=[MockSemgrepAnalyzer(), MockLLMAnalyzer()],
                session=session,
            )
            return AnalysisService(
                repo=repo,
                orchestrator=orchestrator,
                session=session,
            )

        app.dependency_overrides[get_analysis_service] = get_mock_service
    except ImportError:
        pass

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