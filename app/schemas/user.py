from pydantic import BaseModel

class RoleChangeRequest(BaseModel):
    role: str

class AuditorAssignRequest(BaseModel):
    developer_id: str