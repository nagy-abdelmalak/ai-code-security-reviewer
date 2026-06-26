import os

os.environ["JWT_SECRET_KEY"] = "test-secret-for-pytest-that-is-at-least-32-bytes-long!"
os.environ["INITIAL_ADMIN_EMAIL"] = "admin@test.local"
os.environ["INITIAL_ADMIN_PASSWORD"] = "test-password"
os.environ["DATABASE_URL"] = "sqlite:///./test.db"
os.environ["ENVIRONMENT"] = "test"

import pytest
from fastapi.testclient import TestClient
from sqlmodel import Session, SQLModel, create_engine
from sqlmodel.pool import StaticPool

import app.api.routes.submissions as submissions_module
from app.analyzers.port import AnalysisResult, AnalyzerFinding, AnalysisStatus
from app.core.security import hash_password
from app.db.session import get_session
from app.main import app
from app.models import (
    AnalyzerType,
    Severity,
    Role, 
    User
)
from app.services.analysis_service import (
    AnalysisOrchestrator,
    AnalysisService,
    SubmissionRepository
)


# ─── Mock analyzers ────────────────────────────────────────────────────────────

class MockSemgrepAnalyzer:
    """Fake Semgrep — detects hardcoded passwords and eval()."""

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
            line_lower = line.lower()
            if "password" in line_lower and "=" in line:
                findings.append(AnalyzerFinding(
                    severity=Severity.HIGH,
                    line_number=i,
                    rule_id="mock-hardcoded-password",
                    message="Possible hardcoded password detected",
                ))
            if "eval(" in line_lower:
                findings.append(AnalyzerFinding(
                    severity=Severity.HIGH,
                    line_number=i,
                    rule_id="mock-eval-detected",
                    message="Use of eval() detected",
                ))
        return AnalysisResult(
            status=AnalysisStatus.COMPLETED,
            findings=findings,
            duration_ms=10,
        )


class MockLLMAnalyzer:
    """Fake LLM — detects hardcoded passwords and eval()."""
    provider = "mock"      # ← add
    model = "mock-model"   # ← add

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
            line_lower = line.lower()
            if "password" in line_lower and "=" in line:
                findings.append(AnalyzerFinding(
                    severity=Severity.HIGH,
                    line_number=i,
                    rule_id="llm-hardcoded-secret",
                    message="LLM detected a hardcoded secret",
                    explanation=(
                        "Hardcoded secrets can be extracted from source code."
                        if explanation_enabled else None
                    ),
                ))
            if "eval(" in line_lower:
                findings.append(AnalyzerFinding(
                    severity=Severity.HIGH,
                    line_number=i,
                    rule_id="llm-code-injection",
                    message="Use of eval() allows arbitrary code execution",
                    explanation=(
                        "eval() executes any string as code, enabling injection."
                        if explanation_enabled else None
                    ),
                ))
        return AnalysisResult(
            status=AnalysisStatus.COMPLETED,
            findings=findings,
            duration_ms=50,
        )


# ─── Mock service factory ───────────────────────────────────────────────────────

def _make_mock_service(session: Session) -> AnalysisService:
    """Build AnalysisService with both mock analyzers."""
    repo = SubmissionRepository(session)
    orchestrator = AnalysisOrchestrator(
        analyzers=[MockSemgrepAnalyzer(), MockLLMAnalyzer()],
        session=session,
    )
    return AnalysisService(repo=repo, orchestrator=orchestrator, session=session)


# ─── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(name="session")
def session_fixture():
    """In-memory SQLite DB, isolated per test."""
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
    """
    TestClient with:
    - DB overridden to in-memory SQLite
    - get_analysis_service monkey-patched in the routes module
      (plain function, not a Depends — so dependency_overrides won't work)
    """
    # 1. Override DB session
    app.dependency_overrides[get_session] = lambda: session

    # 2. Monkey-patch get_analysis_service in the routes module
    #    Since it's now a plain function called directly (not via Depends),
    #    we replace the reference in the module where it's imported and used.
    original_factory = submissions_module.get_analysis_service


    def mock_factory(session, selected_llms=None, **kwargs):
        print(">>> MOCK FACTORY CALLED <<<")
        analyzers = [MockSemgrepAnalyzer()]
        if selected_llms:  # mirrors real _build_llm_analyzers behavior
            analyzers.append(MockLLMAnalyzer())
        repo = SubmissionRepository(session)
        orchestrator = AnalysisOrchestrator(analyzers=analyzers, session=session)
        return AnalysisService(repo=repo, orchestrator=orchestrator, session=session)

    submissions_module.get_analysis_service = mock_factory

    client = TestClient(app)
    yield client

    # 3. Restore everything after the test
    submissions_module.get_analysis_service = original_factory
    app.dependency_overrides.clear()


@pytest.fixture(name="admin_token")
def admin_token_fixture(client, session):
    """Create bootstrap admin in test DB and return access token."""
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