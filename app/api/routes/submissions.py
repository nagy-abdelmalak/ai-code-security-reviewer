from uuid import UUID
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session, select

from app.core.logging import get_logger
from app.schemas.submission import SubmissionRequest, SubmissionResponse
from app.api.deps import require_role, get_analysis_service, get_session
from app.services.analysis_service import AnalysisService
from app.models import Role, User, Submission, Analysis
from app.models import Finding

router = APIRouter(prefix="/submissions", tags=["submissions"])
logger = get_logger(__name__)

@router.post(
    "/", 
    status_code=status.HTTP_201_CREATED,
    response_model=SubmissionResponse
)
async def submit_code_for_analysis(
    req: SubmissionRequest, 
    user: User = Depends(require_role(Role.DEVELOPER)),
    session: Session = Depends(get_session)
):
    """
    Submit code for analysis. Developer only
    """
    try:
        service = get_analysis_service(session=session)
        submission, analyses = await service.create_and_analyze(
            code=req.code,
            language=req.language.strip().lower(),
            user=user,
            run_llm=req.run_llm,
            explanation_enabled=req.explanation_enabled
        )

        analyses_with_findings = [
            (a, list(session.exec(select(Finding).where(Finding.analysis_id == a.id)).all()))
            for a in analyses
        ]

        return SubmissionResponse.from_orm(submission, analyses_with_findings)
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occured while analyzing your submission: {str(e)}"
        )
    
@router.get("/")
async def list_submissions(
    user: User = Depends(require_role(Role.DEVELOPER)),
    session: Session = Depends(get_session),
    severity: Optional[str] = None,
    status: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None
):
    """
    List current user's submissions (history).
    
    Filters:
    - severity: filter submissions that have at least one finding of this severity
    - status: filter submissions that have at least one finding with this review status
    - date_from/date_to: filter based on create_at dates
    """
    # submissions = service.list_user_submissions(user.id)
    query = (
        select(Submission)
        .where(Submission.user_id == user.id)
        .order_by(Submission.created_at.desc())
    )
    
    # Data filters
    if date_to:
        try:
            dt = datetime.fromisoformat(date_to)
            query = query.where(Submission.created_at >= dt)
        except ValueError:
            pass
    
    if date_from:
        try:
            dt = datetime.fromisoformat(date_from)
            query = query.where(Submission.created_at >= dt)
        except ValueError:
            pass

    submissions = list(session.exec(query).all())

    # severity and status filters require joining through analyses/findings
    if severity or status:
        filtered = []
        for s in submissions:
            analyses = session.exec(
                select(Analysis)
                .where(Analysis.submission_id == s.id)
            ).all()

            dominated = False
            for a in analyses:
                findings = session.exec(
                    select(Finding)
                    .where(Finding.analysis_id == a.id)
                ).all()

                for f in findings:
                    if f.severity.value == severity or f.status.value == status:
                        dominated = True
        
        if dominated:
            filtered.append(s)

        submissions = filtered

    return [
        {
            "id": str(s.id),
            "language": s.language,
            "source_mode": s.source_mode,
            "created_at": s.created_at.isoformat(),
        }
        for s in submissions
    ]

@router.get("/{submission_id}")
async def get_submission(
    submission_id: UUID,
    user: User = Depends(require_role(Role.DEVELOPER, Role.AUDITOR)),
    service: AnalysisService = Depends(get_analysis_service)
):
    """Get a submission with all analyses and findings."""
    result = service.get_submission_with_analyses(submission_id)
    if not result:
        raise HTTPException(status_code=404, detail="Submission not found")
    return result