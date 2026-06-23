import json
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import Response
from sqlmodel import Session, select

from app.core.security import decode_token
from app.core.logging import get_logger
from app.db.session import get_session
from app.models import (
    User,
    Submission,
    Analysis,
    Finding,
    Review
)

logger = get_logger(__name__)
router = APIRouter(prefix="/export", tags=["export"])

def _get_token(request: Request) -> str | None:
    """Read JWT from Authorization header or cookie."""
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.lower().startswith("bearer "):
        return auth_header.split(" ", 1)[1].strip()
    return request.cookies.get("access_token")

def _get_current_user(request: Request, session: Session):
    """Decode JWT from request and return user or None."""
    token = _get_token(request)
    if not token:
        return None
    
    try:
        payload = decode_token(token)
        user_id = payload.get("sub")
        if not user_id or payload.get("type") != "access":
            return None
        user = session.get(User, UUID(user_id))
        return user if user and user.is_active else None
    except Exception:
        return None

@router.get("/{submission_id}/json")
def export_submission_json(
    submission_id:  UUID,
    request: Request,
    session: Session = Depends(get_session)
):
    """
    Export a submission with all analyses and findings as downloadable JSON.
    Used for thesis data analysis.
    """
    user = _get_current_user(request, session)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )

    submission = session.get(Submission, submission_id)
    if not submission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Submission not found"
        )
    
    # Build comprehensive export
    analyses_data = []
    analyses = session.exec(
        select(Analysis).where(Analysis.submission_id == submission_id)
    ).all()

    for analysis in analyses:
        findings = session.exec(
            select(Finding).where(Finding.analysis_id == analysis.id)
        ).all()

        findings_data = []
        for f in findings:
            reviews = session.exec(
                select(Review).where(Review.finding_id == f.id)
            ).all()

            findings_data.append({
                "id": str(f.id),
                "severity": f.severity.value,
                "line_number": f.line_number,
                "rule_id": f.rule_id,
                "message": f.message,
                "explanation": f.explanation,
                "status": f.status.value,
                "reviews": [
                    {
                        "id": str(r.id),
                        "auditor_id": str(r.auditor_id),
                        "proposed_status": r.proposed_status.value if r.proposed_status else None,
                        "comment": r.comment,
                        "created_at": r.created_at.isoformat(),
                    }
                    for r in reviews
                ],
            })

        analyses_data.append({
            "id": str(analysis.id),
            "analyzer_type": analysis.analyzer_type.value,
            "status": analysis.status.value,
            "prompt_version": analysis.prompt_version,
            "ruleset_version": analysis.ruleset_version,
            "explanation_enabled": analysis.explanation_enabled,
            "started_at": analysis.started_at.isoformat() if analysis.started_at else None,
            "completed_at": analysis.completed_at.isoformat() if analysis.completed_at else None,
            "error_message": analysis.error_message,
            "findings_count": len(findings_data),
            "findings": findings_data,
        })

    export_data = {
        "submission": {
            "id": str(submission.id),
            "user_id": str(submission.user_id),
            "language": submission.language,
            "source_mode": submission.source_mode,
            "code_lines": len(submission.code.splitlines()),
            "created_at": submission.created_at.isoformat(),
        },
        "analyses": analyses_data,
        "metadata": {
            "export_format": "json",
            "export_version": "1.0",
        },
    }

    # Return as downloadable file
    return Response(
        content=json.dumps(export_data, indent=2),
        media_type="application/json",
        headers={
            "Content-Disposition": f"attachment; filename=submission_{submission_id}.json"
        },
    )
