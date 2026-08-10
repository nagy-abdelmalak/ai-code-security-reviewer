
from uuid import uuid4

from app.models import Finding, Severity
from app.rag.port import Chunk, RetrievedChunk
from app.services.grounding_service import GroundingService

class FakeRetriever:
    def __init__(self, results: list[RetrievedChunk]):
        self._results = results
    
    def retrieve(self, query: str, top_k: int = 5) -> list[RetrievedChunk]:
        return self._results[:top_k]

def _chunk(source_id: str, section: str) -> Chunk:
    return Chunk(
        source="cwe",
        source_id=source_id,
        title=f"Title for {source_id}",
        url=f"https://cwe.mitre.org/{source_id}",
        section=section,
        content="..."
    )

def _finding(message: str) -> Finding:
    return Finding(
        analysis_id=uuid4(),
        severity=Severity.HIGH,
        line_number=1,
        rule_id="test_rule",
        message=message
    )

def test_repeated_source_keeping_best_score():
    results = [
        RetrievedChunk(chunk=_chunk("CWE-89", "Description"), score=0.9),
        RetrievedChunk(chunk=_chunk("CWE-89", "Mitigations"), score=0.7),
        RetrievedChunk(chunk=_chunk("CWE-79", "Description"), score=0.5)
    ]
    svc = GroundingService(FakeRetriever(results))

    citations = svc.ground_finding(_finding("sql injection"), top_k=3)

    assert [c.source_id for c in citations] == ["CWE-89", "CWE-79"]
    assert citations[0].score == 0.9


def test_citations_stay_ordered_best_first():
    results = [
        RetrievedChunk(chunk=_chunk("CWE-89", "d"), score=0.8),
        RetrievedChunk(chunk=_chunk("CWE-22", "d"), score=0.6),
        RetrievedChunk(chunk=_chunk("CWE-79", "d"), score=0.4)
    ]
    svc = GroundingService(FakeRetriever(results))
    scores = [c.score for c in svc.ground_finding(_finding("x"), top_k=3)]
    assert scores == sorted(scores, reverse=True)

def test_citations_metadata():
    results = [
        RetrievedChunk(chunk=_chunk("CWE-89", "Description"), score=0.9)
    ]
    svc = GroundingService(FakeRetriever(results))
    c = svc.ground_finding(_finding("x"), top_k=1)[0]
    assert c.source_id == "CWE-89"
    assert c.title == "Title for CWE-89"
    assert c.url.endswith("CWE-89")

def test_no_results_returns_empty_list():
    svc = GroundingService(FakeRetriever([]))
    assert svc.ground_finding(_finding("nothing matches"), top_k=3) == []