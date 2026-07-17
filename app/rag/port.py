# app/rag/port.py
"""
Ports (interfaces) for the RAG module.  Mirrors app/analyzers/port.py.

The services and scripts depend ONLY on these Protocols, never on the concrete
SentenceTransformer / pgvector classes. That means you can swap the embedding
model or the vector store later without touching the code that uses them —
the same Ports & Adapters idea you already applied to the analyzers (ADR-003).
"""

from dataclasses import dataclass
from typing import Protocol, Sequence, runtime_checkable


@dataclass(frozen=True)
class Chunk:
    """
    One retrievable piece of a knowledge document (e.g. a section of CWE-89).

    This is the *domain* object that flows through the RAG pipeline before it
    is persisted. The DB model (KnowledgeChunk) mirrors these fields plus the
    embedding vector. Keeping a plain frozen dataclass here — separate from the
    SQLModel table — keeps chunking/embedding logic testable without a DB.
    """
    source: str          # "cwe" | "owasp"  (see constants.py)
    source_id: str       # e.g. "CWE-89", "A03:2021"
    title: str           # human title, e.g. "Improper Neutralization of Special Elements..."
    url: str             # canonical source URL, used later for citations
    section: str | None  # sub-heading this chunk came from, if any
    content: str         # the actual text that gets embedded


@dataclass(frozen=True)
class RetrievedChunk:
    """A chunk returned from a similarity search, with its relevance score."""
    chunk: Chunk
    score: float         # cosine similarity in [0, 1]; higher = more relevant


@runtime_checkable
class Embedder(Protocol):
    """
    Turns text into vectors.

    Two methods on purpose: many embedding models are trained asymmetrically
    (documents vs. queries get slightly different treatment). Even when they
    are symmetric, having both makes call sites read clearly and lets us swap
    in an asymmetric model later with no changes upstream.
    """

    @property
    def dim(self) -> int:
        """Vector dimension. MUST equal constants.EMBEDDING_DIM."""
        ...

    def embed_documents(self, texts: Sequence[str]) -> list[list[float]]:
        """Embed a batch of documents (ingestion path)."""
        ...

    def embed_query(self, text: str) -> list[float]:
        """Embed a single query (retrieval path)."""
        ...


@runtime_checkable
class KnowledgeRetriever(Protocol):
    """
    Finds the most relevant knowledge chunks for a piece of text.
    Implemented by PgVectorKnowledgeStore in slice 3.
    """

    def retrieve(self, query: str, top_k: int = 5) -> list[RetrievedChunk]:
        """Return the top_k most similar chunks to `query`, best first."""
        ...