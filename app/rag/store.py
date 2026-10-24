from sqlmodel import Session, select

from app.models import KnowledgeChunk
from app.db.session import engine
from app.rag.port import Embedder, RetrievedChunk, Chunk
from app.rag.embedder import SentenceTransformerEmbedder


class PgVectorKnowledgeStore:
    """Implements app.rag.port.knowledgeRetriver over pgvector"""

    def __init__(self, session: Session, embedder: Embedder):
        self.session = session
        self.embedder = embedder

    def retrieve(self, query: str, top_k: int = 5) -> list[RetrievedChunk]:
        vector = self.embedder.embed_query(query)

        distance = KnowledgeChunk.embedding.cosine_distance(vector)
        statement = (
            select(KnowledgeChunk, distance)
            .order_by(distance)
            .limit(top_k)
        )

        rows = self.session.exec(statement).all()

        results = []
        for kc, dist in rows:
            results.append(
                RetrievedChunk(
                    chunk= Chunk(
                        source=kc.source,
                        source_id=kc.source_id,
                        title=kc.title,
                        url=kc.url,
                        section=kc.section,
                        content=kc.content
                    ),
                    score = 1.0 - dist
                )
            )

        return results

if __name__ == "__main__":
    with Session(engine) as session:
        store = PgVectorKnowledgeStore(session=session, embedder=SentenceTransformerEmbedder())
        for r in store.retrieve("SQL injextion via. string concatenation", top_k=3):
            print(f"{r.score:.3f} {r.chunk.source_id}")
            print(f"{r.chunk.section}")
            print(f"{r.chunk.content}")
            print()