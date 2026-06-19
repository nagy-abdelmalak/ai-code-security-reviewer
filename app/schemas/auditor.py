from pydantic import BaseModel

class RoleChangeRequest(BaseModel):
    role: str

class AuditorAssignRequest(BaseModel):
    developer_id: str

class AuditorAssignResponse(BaseModel):
    assignment_id: str
    status: str