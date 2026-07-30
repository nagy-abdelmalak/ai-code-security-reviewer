"""
Ports (interfaces) for RAG module, mirroring app/analyzers/port.py (ADR-003),
in order to easily swap models or vector store later without touching the code.
"""

from dataclasses import dataclass
from typing import Protocol, Sequence, runtime_checkable

@dataclass(frozen=True)
class Chunk:
    """A retrivable piece of knowledge document (e.g. a section of CWE-89)"""
    source: str             # "cwe" | "owasp" (see constants.py)
    source_id: str          # e.g. "CWE-89" or "A03:2021"
    title: str              # e.g. "Improper neutralization of special elements ..."
    url: str                # URL of the source, used later for citations
    section: str | None     # sub-heading where the chunk came from, if any
    content: str            # the actual text that gets embedded 

@dataclass(frozen=True)
class RetrievedChunk:
    """A chunk returned after similarity search, with its relevance score."""
    chunk: Chunk
    score: float

@dataclass(frozen=True)
class Citation:
    source_id: str
    title: str
    url: str
    score: float

@runtime_checkable
class Embedder(Protocol):
    """Turns text into vectors
    
    2 methods on purpose to cover symmetric and unsymmetric models
    """

    @property
    def dim(self) -> int:
        """Vector dimension, MUST equal constants.EMBEDDING_DIM"""
        ...

    def embed_documents(self, text: Sequence[str]) -> list[list[float]]:
        """Embed a patch of documents (ingestation path)"""
        ...
    
    def embed_query(self, text: str) -> list[float]:
        """Embed a single query (retrieval path)"""
        ...

@runtime_checkable
class KnowledgeRetriever(Protocol):
    """
    Finds the most relevant knowledge chunks for a piece of text.
    Implemented by PgVectorKnowledgeStore
    """
    
    def retrieve(self, query: str, top_k: int = 5) -> list[RetrievedChunk]:
        """Return the top_k most similar chunks"""
        ...