"""
Shared constants for the RAG module.

WHY a dedicated module: the embedding dimension is needed in TWO places that
must never disagree: DB column type (Vector(EMBEDDING_DIM)) and the
embedder that produces the vectors. Fails loudly in case they're different.

NOTE: EMBEDDING_DIM is baked into the Postgres column type.
Changing the embedding model to one with a different dimension is therefore a
*schema change*, as consequence the column must be migrated AND
re-embeded for every stored chunk.
"""

# all-MiniLM-L6-v2 -> 384 dimensions. Small, fast, CPU-friendly, well known.
DEFAULT_EMBEDDING_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
EMBEDDING_DIM = 384

# Knowledge source identifiers (stored in KnowledgeChunk.source).
SOURCE_CWE = "cwe"
SOURCE_OWASP = "owasp"