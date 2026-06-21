from pydantic import BaseModel, Field
from typing import Self

class ReviewRequest(BaseModel):
    proposed_status: str | None = Field(
        default=None,
        description="One of: confirmed, false_positive, accepted_risk. Null for comment-only"
    )
    comment: str | None = Field(
        default=None,
        max_length=2000,
    )

class ReviewResponse(BaseModel):
    id: str
    finding_id: str
    auditor_id: str
    proposed_status: str | None
    comment: str | None
    created_at: str

    @classmethod
    def from_orm(cls, review) -> Self:
        return cls(
            id=str(review.id),
            finding_id=str(review.finding_id),
            auditor_id=str(review.auditor_id),
            proposed_status=review.proposed_status.value if review.proposed_status else None,
            comment=review.comment,
            created_at=review.created_at.isoformat(),
        )