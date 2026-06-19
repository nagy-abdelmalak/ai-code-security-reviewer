from fastapi import APIRouter, Depends, HTTPException, status
from sqlmodel import Session
from uuid import UUID

from app.services.user_service import UserService, UserNotFound, InvalidRole
from app.db.session import get_session
from app.models import User, Role
from app.api.routes.deps import require_role
from app.schemas.auth import UserResponse
from app.schemas.user import (
    RoleChangeRequest, 
    AuditorAssignRequest, 
    AuditorAssignResponse
)

router = APIRouter(prefix="/users", tags=["users"])

@router.get("/", response_model=list[UserResponse])
def list_users(
    admin: User = Depends(require_role(Role.ADMIN)),
    session: Session = Depends(get_session())
):
    service = UserService(session)
    users = service.list_users()
    
    return [
        UserResponse(id=str(u.id), email=u.email, role=u.role.value)
        for u in users
    ]

@router.put("/{user_id}/role", response_model=UserResponse)
def change_role(
    user_id: UUID,
    req: RoleChangeRequest,
    session: Session = Depends(get_session),
    admin: User = Depends(require_role(Role.ADMIN))
):
    service = UserService(session)
    try:
        target = UserService.change_role(user_id, req.role, admin=admin)
    except UserNotFound:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    except InvalidRole as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    
    return UserResponse(id=str(target.id), email=target.email, role=target.role.value)

@router.post(
    "/assign-auditor", 
    status_code=status.HTTP_201_CREATED,
    response_model=AuditorAssignResponse
)
def assign_auditor(
    req: AuditorAssignRequest,
    admin: User = Depends(require_role(Role.ADMIN)),
    session: Session = Depends(get_session)
):
    service = UserService(session)
    try:
        assignment = service.assign_auditor(
            developer_id=req.developer_id,
            auditor_id=admin.id,
            admin=admin
        )
    except InvalidRole as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    
    return {"assignment_id": str(assignment.id), "status": "assigned"}