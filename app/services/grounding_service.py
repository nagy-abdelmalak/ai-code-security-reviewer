from app.rag import KnowledgeRetriever, Citation
from app.models import Finding

class GroundingService:
    def __init__(self, retriever: KnowledgeRetriever):
        self.retriever = retriever

    def ground_finding(self, finding: Finding, top_k: int = 3) -> list[Citation]:
        query = finding.message
        results = self.retriever.retrieve(query=query, top_k=top_k * 4)

        seen: set[str] = set()
        citations: list[Citation] = []
        for r in results:
            s_id = r.chunk.source_id
            if s_id in seen:
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

        return citations

