from app.core.security import hash_password
from app.models.analysis import Analysis, AnalysisStatus, AnalyzerType
from app.models.auditor_assignment import AuditorAssignment
from app.models.finding import Finding, Severity, FindingStatus
from app.models.submission import Submission
from app.models.user import Role, User


def _setup_finding_with_auditor(session):
    """
    Create a full chain: developer → submission → analysis → finding,
    plus an auditor assigned to that developer. Returns (auditor_token_data, finding).
    """
    # Developer
    developer = User(
        email="dev@example.com",
        password_hash=hash_password("devpassword"),
        role=Role.DEVELOPER,
    )
    session.add(developer)
    session.flush()

    # Auditor
    auditor = User(
        email="auditor@example.com",
        password_hash=hash_password("auditorpassword"),
        role=Role.AUDITOR,
    )
    session.add(auditor)
    session.flush()

    # Assignment
    assignment = AuditorAssignment(
        auditor_id=auditor.id,
        developer_id=developer.id,
    )
    session.add(assignment)

    # Submission → Analysis → Finding
    submission = Submission(user_id=developer.id, code="x = 1", language="python")
    session.add(submission)
    session.flush()

    analysis = Analysis(
        submission_id=submission.id,
        analyzer_type=AnalyzerType.SEMGREP,
        status=AnalysisStatus.COMPLETED,
    )
    session.add(analysis)
    session.flush()

    finding = Finding(
        analysis_id=analysis.id,
        severity=Severity.HIGH,
        line_number=1,
        rule_id="test-rule",
        message="Test finding",
    )
    session.add(finding)
    session.commit()
    session.refresh(finding)
    session.refresh(auditor)
    session.refresh(developer)

    return developer, auditor, finding


def _login(client, email, password):
    resp = client.post("/auth/login", json={"email": email, "password": password})
    return resp.json()["access_token"]


def test_auditor_can_confirm_finding(client, session):
    developer, auditor, finding = _setup_finding_with_auditor(session)
    token = _login(client, "auditor@example.com", "auditorpassword")

    response = client.post(
        f"/findings/{finding.id}/reviews",
        json={"proposed_status": "confirmed", "comment": "Real vulnerability"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["proposed_status"] == "confirmed"
    assert body["comment"] == "Real vulnerability"

    # Verify finding status was updated
    session.refresh(finding)
    assert finding.status == FindingStatus.CONFIRMED


def test_auditor_can_mark_false_positive(client, session):
    developer, auditor, finding = _setup_finding_with_auditor(session)
    token = _login(client, "auditor@example.com", "auditorpassword")

    response = client.post(
        f"/findings/{finding.id}/reviews",
        json={"proposed_status": "false_positive", "comment": "Not a real issue"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 201

    session.refresh(finding)
    assert finding.status == FindingStatus.FALSE_POSITIVE


def test_comment_only_review_does_not_change_status(client, session):
    developer, auditor, finding = _setup_finding_with_auditor(session)
    token = _login(client, "auditor@example.com", "auditorpassword")

    response = client.post(
        f"/findings/{finding.id}/reviews",
        json={"comment": "Need to investigate further"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 201

    session.refresh(finding)
    assert finding.status == FindingStatus.UNREVIEWED  # unchanged


def test_developer_cannot_review(client, session):
    developer, auditor, finding = _setup_finding_with_auditor(session)
    token = _login(client, "dev@example.com", "devpassword")

    response = client.post(
        f"/findings/{finding.id}/reviews",
        json={"proposed_status": "confirmed"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403


def test_unassigned_auditor_cannot_review(client, session):
    _, _, finding = _setup_finding_with_auditor(session)

    # Create a second auditor NOT assigned to the developer
    unassigned = User(
        email="rogue@example.com",
        password_hash=hash_password("roguepassword"),
        role=Role.AUDITOR,
    )
    session.add(unassigned)
    session.commit()

    token = _login(client, "rogue@example.com", "roguepassword")

    response = client.post(
        f"/findings/{finding.id}/reviews",
        json={"proposed_status": "confirmed"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403


def test_list_reviews_for_finding(client, session):
    developer, auditor, finding = _setup_finding_with_auditor(session)
    token = _login(client, "auditor@example.com", "auditorpassword")

    # Add two reviews
    client.post(
        f"/findings/{finding.id}/reviews",
        json={"comment": "First look"},
        headers={"Authorization": f"Bearer {token}"},
    )
    client.post(
        f"/findings/{finding.id}/reviews",
        json={"proposed_status": "confirmed", "comment": "Confirmed after review"},
        headers={"Authorization": f"Bearer {token}"},
    )

    response = client.get(
        f"/findings/{finding.id}/reviews",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    assert len(response.json()) == 2