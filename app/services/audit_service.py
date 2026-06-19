import json
from sqlmodel import Session
from uuid import UUID

from app.models import EventType, AuditEvent
from app.core.logging import get_logger

logger = get_logger(__name__)

class AuditService:
    """
    Append-only audit logger, called by other services in the same 
    DB transaction to ensure consistency (ADR-009)
    """
    def __init__(self, session: Session):
        self.session = session

    def log(
            self,
            user_id: UUID,
            event_type: EventType,
            details: dict | None
    ) -> AuditEvent:
        event = AuditEvent(
            user_id=user_id,
            event_type=event_type,
            details=json.dumps(details or {})
        )
        self.session.add(event)

        logger.info(
            "audit_event",
            event_type=event_type.value,
            user_id=str(user_id),
            details=details
        )
        return event