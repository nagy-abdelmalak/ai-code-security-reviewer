"""
KnowledgeChunk: a chunk of the documentation (in this case CWE/OWASP) + its embedding vecotor

The `embedding` column uses pgvector's Vector type. SQLModel dosen't know that type natively,
so it gets passed via sa_column=Column(Vector(...))
"""

from datetime import datetime, timezone
from uuid import UUID, uuid4
from pgvector.sqlalchemy import Vector
from sqlalchemy import Column
from sqlmodel import SQLModel, Field

from app.rag.constants import EMBEDDING_DIM

class KnowledgeChunk(SQLModel, table=True):
    """Embedded chunk of knowledge"""
    __tablename__ = "knowledge_chunk"

    id: UUID = Field(default_factory=uuid4, primary_key=True)
    source: str = Field(index=True)
    source_id: str = Field(index=True)
    title: str
    url: str
    section: str | None = None
    content: str
    embedding: list[float] = Field(sa_column=Column(Vector(EMBEDDING_DIM)))
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )