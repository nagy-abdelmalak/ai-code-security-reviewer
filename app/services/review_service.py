from sqlmodel import Session, select
from uuid import UUID

from app.services.audit_service import AuditService
from app.core.logging import get_logger
from app.models import (
    Review, 
    Finding, 
    User, 
    FindingStatus, 
    EventType,
    Analysis,
    Submission,
    AuditorAssignment
)

logger = get_logger(__name__)

class FindingNotFound(Exception):
    pass

class InvalidStatus(Exception):
    pass

class NotAssignedAuditor(Exception):
    pass

class ReviewService:
    def __init__(self, session: Session):
        self.session = session
        self.audit = AuditService(session)
    
    def create_review(
            self,
            finding_id: UUID,
            auditor: User,
            proposed_status_str: str | None,
            comment: str | None
    ) -> Review:
        # 1. Find the Finding
        finding = self.session.get(Finding, finding_id)
        if not finding:
            raise FindingNotFound(str(finding_id))
        
        # 2. Verify auditor is assigned to the developer who own this code
        self._verify_assigned_developer(auditor, finding)

        # 3. Validate proposed_status if provided
        proposed_status = None
        if proposed_status_str:
            try:
                proposed_status = FindingStatus(proposed_status_str)
                if proposed_status == FindingStatus.UNREVIEWED:
                    raise InvalidStatus("Cannot set status back to unreviewed")
            except ValueError:
                raise InvalidStatus(f"Invalid status: {proposed_status_str}")
            
        # 4. Create and review
        review = Review(
            finding_id=finding_id,
            auditor_id=auditor.id,
            proposed_status=proposed_status,
            comment=comment
        )
        self.session.add(review)

        # 5. Update finding status if proposed
        if proposed_status:
            old_status = finding.status
            finding.status = proposed_status
            logger.info(
                "finding_staus_updated",
                finding_id=str(finding_id),
                old_status=old_status.value,
                new_status=proposed_status.value,
                auditor_id=str(auditor.id),
            )

        # 6. Audit log
        self.audit.log(
            user_id=auditor.id,
            event_type=EventType.REVIEW_CREATED,
            details={
                "finding_id": str(finding_id),
                "proposed_status": proposed_status.value if proposed_status else None,
                "comment": comment,
            }
        )
        
        self.session.commit()
        self.session.refresh(review)

        logger.info(
            "review_created",
            review_id=str(review.id),
            finding_id=str(finding_id),
            auditor_id=str(auditor.id),
            is_verdict=proposed_status is not None,
        )

        return review
    
    def _verify_assigned_developer(
            self,
            auditor: User,
            finding: Finding
    ):
        analysis = self.seession.get(Analysis, finding.analysis_id)
        if not analysis:
            FindingNotFound("Analysis not found")
        
        submission = self.session.get(Submission, analysis.submission_id)
        if not submission:
            FindingNotFound("Submission not found")

        assignment = self.session.exec(
            select(AuditorAssignment).where(
                AuditorAssignment.auditor_id == auditor.id,
                AuditorAssignment.developer_id == submission.user_id
            )
        ).first()

        if not assignment:
            logger.warning(
                "review_denied",
                auditor_id=str(auditor.id),
                developer_id=str(submission.user_id),
                reason="not_assigned",
            )
            raise NotAssignedAuditor(
                "You are not assigned to review this developer's code"
            )

    def get_reviews_for_finding(self, finding_id: UUID) -> list[Review]:
        """Get all reviews (discussion thread) for a finding."""
        return list(
            self.session.exec(
                select(Review)
                .where(Review.finding_id == finding_id)
                .order_by(Review.created_at)
            ).all()
        )
            



        

        