from sqlmodel import Session, select
from uuid import UUID

from app.services.audit_service import AuditService
from app.models import User, Role, EventType, AuditorAssignment
from app.core.logging import get_logger

logger = get_logger(__name__)

class InvalidRole(Exception):
    pass

class UserNotFound(Exception):
    pass

class UserService:
    def __init__(self, session: Session):
        self.session = session
        self.audit = AuditService(session)

    def list_users(self) -> list[User]:
        return list(self.session.exec(select(User)).all())
    
    def change_role(self, target_user_id: UUID, new_role_str: str, admin: User) -> User:
        # validate role string
        try:
            new_role = Role(new_role_str)
        except ValueError:
            logger.warning("invalid_role", new_role=new_role_str)
            raise InvalidRole(f"Invalid role: {new_role_str}")

        target = self.session.get(User, target_user_id)
        if not target:
            logger.warning("user_not_found", target_user_id=target_user_id)
            raise UserNotFound(str(target_user_id))
        
        old_role = target.role
        target_role = new_role

        self.audit.log(
            admin.id, 
            EventType.ROLE_CHANGED, 
            {
                "target_user_id": str(target.id),
                "old_role": old_role.value,
                "new_role": new_role.value
            }
        )
        self.session.commit()
        self.session.refresh(target)

        logger.info(
            "role_changed",
            admin_id=str(admin.id),
            target_user_id=str(target.id),
            old_role=old_role.value,
            new_role=new_role.value
        )
        
        return target
    
    def assign_auditor(self, developer_id: UUID, auditor_id: UUID, admin: User):
        developer = self.session.get(User, developer_id)
        auditor = self.session.get(User, auditor_id)

        if not developer or developer.role != Role.DEVELOPER:
            logger.warning("target_developer_not_valid")
            raise InvalidRole("Target developer is not valid")
        if not auditor or auditor.role != Role.AUDITOR:
            logger.warning("target_auditor_not_valid")
            raise InvalidRole("Target auditor is not valid")
        
        assignment = AuditorAssignment(
            auditor_id=auditor.id,
            developer_id=developer.id
        )
        self.session.add(assignment)
        self.session.commit()
        self.session.refresh(assignment)

        logger.info(
            "auditor_assigned",
            auditor_id=str(auditor.id),
            developer_id=str(developer.id),
            admin_id=str(admin.id)
        )

        return assignment
