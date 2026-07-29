"""
Loads the knowledge corpus from data knowledge/*.json, chunks it and embeds it and
stores it in the knowledge_chunk table. Safe to re-run (idempotent).
"""

import sys
from pathlib import Path
import json
import time
from sqlmodel import Session, SQLModel, delete
from collections import defaultdict

from app.core.logging import get_logger
from app.rag.chunker import Section, chunk_document
from app.rag.port import Chunk, Embedder
from app.rag.embedder import SentenceTransformerEmbedder
from app.rag.constants import SOURCE_CWE
from app.rag.setup import ensure_pgvector, create_vector_index
from app.models import KnowledgeChunk
from app.db.session import engine

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

REQUIRED = {"id", "title", "url", "sections"}
DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "knowledge"

logger = get_logger(__name__)

def load_documents(data_dir: Path) -> list[dict]:
    parsed_dicts = []

    for file_path in sorted(data_dir.glob("*.json")):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                missing = REQUIRED - data.keys()
                if missing:
                    logger.warning("knowledge_file_missing_keys", file=file_path.name, missing=sorted(missing))
                    continue
                parsed_dicts.append(data)
        except (json.JSONDecodeError, OSError, UnicodeDecodeError) as e:
            logger.warning("knowledge_file_unreadable", file=file_path.name, error=str(e))
            continue
    
    count = len(parsed_dicts)
    if count < 1:
        logger.warning("no_docs_found", count=count)

    logger.info("knowledge_documents_loaded", count=count)

    return parsed_dicts

def to_chunks(doc: dict) -> list[Chunk]:
    sections = [Section(heading=s["heading"], text=s["text"]) for s in doc["sections"]]

    chunks = chunk_document(
        source=SOURCE_CWE,
        source_id=doc["id"],
        title=doc["title"],
        url=doc["url"],
        sections=sections
    )

    return chunks
    
def embed_chunks(
    embedder: Embedder,
    chunks: list[Chunk]
) -> list[list[float]]:
    texts = [c.content for c in chunks]
    
    start = time.monotonic()
    vectors = embedder.embed_documents(texts)
    elapsed = int((time.monotonic() - start) * 1000)

    print(f"In {elapsed} ms")
    print(vectors[0][:5])

    assert len(vectors) == len(chunks), f"{len(vectors)} vectors for {len(chunks)} chunks"

    logger.info(
        "chunks_embedded",
        count=len(vectors),
        dim=len(vectors[0]) if vectors else 0,
        duration_ms=elapsed,
    )

    return vectors

def persist(
    session: Session,
    source_id: str,
    chunks: list[Chunk],
    vectors: list[list[float]]
) -> int:
    session.exec(delete(KnowledgeChunk).where(KnowledgeChunk.source_id == source_id))

    for c, v in zip(chunks, vectors):
        knowledge_chunk = KnowledgeChunk(
            source=c.source,
            source_id=c.source_id,
            title=c.title,
            url=c.url,
            section=c.section,
            content=c.content,
            embedding=v
        )
        session.add(knowledge_chunk)
    
    session.flush()
    
    count = len(chunks)

    logger.info("knowledge_chunks_saved_db", source_id=source_id, count=count)

    return count

def main() -> None:
    start = time.monotonic()

    ensure_pgvector(engine)
    SQLModel.metadata.create_all(engine)

    documents = load_documents(DATA_DIR)
    chunks = [c for d in documents for c in to_chunks(d)]
    embedder = SentenceTransformerEmbedder()
    vectors = embed_chunks(embedder=embedder, chunks=chunks)
    
    by_doc: dict[str, list[tuple[Chunk, list[float]]]] = defaultdict(list)
    for c, v in zip(chunks, vectors):
        by_doc[c.source_id].append((c,v))
    
    total = 0
    with Session(engine) as session:
        try:
            for doc in documents:
                pairs = by_doc[doc["id"]]
                doc_chunks = [c for c, _ in pairs]
                doc_vectors = [v for _, v in pairs]
                total += persist(
                    session=session,
                    source_id=doc["id"],
                    chunks=doc_chunks,
                    vectors=doc_vectors
                )
                session.commit()
        except Exception:
            session.rollback()

            logger.exception("ingestation_failed")

            raise

    create_vector_index(engine)
        
    elapsed = int((time.monotonic() - start) * 1000)

    logger.info(
        "ingestion_complete",
        documents=len(documents),
        chunks=total,
        duration_ms=elapsed,
    )

if __name__ == "__main__":
    main()
