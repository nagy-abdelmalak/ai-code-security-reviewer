"""RAG module: embeddings, chunking and pgvector-backed retrieval."""

from app.rag.port import (
    Chunk,
    RetrievedChunk,
    Embedder,
    KnowledgeRetriever,
    Citation
)
from app.rag.embedder import SentenceTransformerEmbedder
from app.rag.chunker import Section, chunk_document

__all__ = [
    "Chunk",
    "RetrievedChunk",
    "Embedder",
    "KnowledgeRetriever",
    "SentenceTransformerEmbedder",
    "Section",
    "chunk_document",
    "Citation"
]