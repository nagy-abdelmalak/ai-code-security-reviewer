"""
The `vector` type only exists after `CREATE EXTENSION vector`, this statement
must run BEFORE SQLModel.metadata.create_all() tries to create a column of type
Vector(384), otherwise Postgresql will throw an error
"""

from sqlalchemy import text
from sqlalchemy.engine import Engine

from app.core.logging import get_logger

logger = get_logger(__name__)

def ensure_pgvector(engine: Engine) -> None:
    """Create the pgvector extension if it isn't already installed"""
    with engine.begin() as conn:
        conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector"))
    logger.info("pgvector_extension_ready")

def create_vector_index(engine: Engine) -> None:
    """HNSW index for cosine similarity. Run AFTER the corpus is loaded"""
    with engine.begin() as conn:
        conn.execute(text(
            "CREATE INDEX IF NOT EXISTS knowledge_chunk_embedding_hnsw " \
            "ON knowledge_chunk USING hnsw (embedding vector_cosine_ops)"
        ))
    logger.info("vector_index_ready", kind="hnsw", ops="vector_cosine_ops")