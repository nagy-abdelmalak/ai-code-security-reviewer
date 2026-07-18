"""
SentenceTransformer embedder (concrete adapter for the Embedder port).

- Model weights (~90MB) are loaded once in __init__; construct once, reuse.
- normalize_embeddings=True -> unit-length vectors, so cosine similarity and
  dot product are equivalent (matters for the pgvector cosine index).
- The model's real dimension is checked against EMBEDDING_DIM at startup, so a
  wrong model fails loudly instead of producing vectors the DB will reject.
"""

from app.core.logging import get_logger
from app.rag.constants import DEFAULT_EMBEDDING_MODEL, EMBEDDING_DIM
from sentence_transformers import SentenceTransformer

logger = get_logger(__name__)

class SentenceTransformerEmbedder:
    """
    Local and CPU-friendly embeddings
    
    Implements app.rag.port.Embedder
    """
    def __init__(self, model_name: str = DEFAULT_EMBEDDING_MODEL) -> None:
        logger.info("embdder_loading", model=model_name)
        self._model = SentenceTransformer(model_name)
        self._dim = self._model.get_embedding_dimension()

        if self._dim != EMBEDDING_DIM:
            raise ValueError(
                f"Embedding model '{model_name}' produces {self._dim}-dim vectors "
                f"but the DB schema expects {EMBEDDING_DIM}. Update "
                "constants.EMBEDDING_DIM and re-create the knowledge_chunk table."
            )
        
        logger.info("embedder_ready", model=model_name, dim=self._dim)

    @property
    def dim(self) -> int:
        return self._dim
    
    def embed_documents(self, texts) -> list[list[float]]:
        vectors = self._model.encode(
            list(texts),
            normalize_embaddings=True,
            show_progress_bar=False
        )
        return [v.tolist() for v in vectors]
    
    def embed_query(self, text: str) -> list[float]:
        vector = self._model.encode(
            text,
            normalize_embeddings=True,
            show_progress_bar=False
        )
        return vector.tolist()