from uuid import UUID
from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session

from app.api.deps import require_role
from app.core.logging import get_logger
from app.db.session import get_session
from app.models.user import Role, User
from app.schemas.review import ReviewRequest, ReviewResponse
from app.services.review_service import (
    FindingNotFound,
    InvalidStatus,
    NotAssignedAuditor,
    ReviewService,
)

logger = get_logger(__name__)

router = APIRouter(prefix="/findings", tags=["reviews"])

@router.post(
    "/{finding_id}/reviews",
    response_model=ReviewResponse,
    status_code= status.HTTP_201_CREATED
)
def create_review(
    finding_id: UUID,
    req: ReviewRequest,
    auditor: User = Depends(require_role(Role.AUDITOR)),
    session: Session = Depends(get_session)
):
    """Add a review to a finiding (Auditor only)"""
    service = ReviewService(session)
    try:
        review = service.create_review(
            finding_id=finding_id,
            auditor=auditor,
            proposed_status_str=req.proposed_status,
            comment=req.comment
        )
    except FindingNotFound:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail="Fiding not found"
        )
    except NotAssignedAuditor as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, 
            detail=str(e)
        )
    except InvalidStatus as e:
        raise HTTPException(
            status_code=status.HTTP_400_FORBIDDEN, 
            detail=str(e)
        )

    return ReviewResponse.from_orm(review)

@router.get("/{finding_id}/reviews", response_model=list[ReviewResponse])
def list_reviews(
    finding_id: UUID,
    user: User = Depends(require_role(Role.DEVELOPER, Role.AUDITOR)),
    session: Session = Depends(get_session),
):
    """Get all reviews for a finding. Developer and Auditor."""
    service = ReviewService(session)
    reviews = service.get_reviews_for_finding(finding_id)
    return [ReviewResponse.from_orm(r) for r in reviews]