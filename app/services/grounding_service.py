from app.rag import KnowledgeRetriever, Citation
from app.models import Finding, Severity
from app.core.config import settings

class GroundingService:
    def __init__(self, retriever: KnowledgeRetriever):
        self.retriever = retriever

    def ground_finding(self, finding: Finding, top_k: int = 3) -> list[Citation]:
        return self.ground_message(self, finding.message, top_k)

    def ground_message(self, query: str, top_k: int) -> list[Citation]:
        results = self.retriever.retrieve(query=query, top_k=top_k * 4)

        seen: set[str] = set()
        citations: list[Citation] = []
        for r in results:
            s_id = r.chunk.source_id
            if s_id in seen or r.score < settings.RAG_MIN_SCORE:
                continue
            seen.add(s_id)
            citations.append(
                Citation(
                    source_id=s_id,
                    title=r.chunk.title,
                    url=r.chunk.url,
                    score=r.score
                )
            )

        return citations[:top_k]    # at most top_k DISTINCT sources

if __name__ == "__main__":
    from app.db.session import engine
    from app.rag.embedder import SentenceTransformerEmbedder
    from app.rag.store import PgVectorKnowledgeStore
    from sqlmodel import Session
    from uuid import uuid4
    from app.models import Finding, Severity

    with Session(engine) as session:
        store = PgVectorKnowledgeStore(session, SentenceTransformerEmbedder())
        svc = GroundingService(store)
        finding = Finding(
            analysis_id=uuid4(), severity=Severity.HIGH, line_number=12,
            rule_id="py-sql-concat",
            message="user input concatenated directly into SQL query",
        )
        for c in svc.ground_finding(finding, top_k=3):
            print(f"{c.score:.3f}  {c.source_id}  {c.title}")