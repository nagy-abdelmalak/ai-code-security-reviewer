from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session, select

from app.core.logging import get_logger
from app.schemas.submission import SubmissionRequest, SubmissionResponse
from app.api.deps import require_role, get_analysis_service, get_session
from app.services.analysis_service import AnalysisService
from app.models import Role, User
from app.models import Finding, Analysis, Submission

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
    service: AnalysisService = Depends(get_analysis_service),
    session: Session = Depends(get_session)
):
    """
    Submit code for analysis. Developer only
    """
    try:
        submission, analyses = await service.create_and_analyze(
            code=req.code,
            language=req.language,
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
    service: AnalysisService = Depends(get_analysis_service),
):
    """List current user's submissions (history)."""
    submissions = service.list_user_submissions(user.id)
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