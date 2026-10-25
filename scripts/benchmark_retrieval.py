import sys
import json
from pathlib import Path
from sqlmodel import Session

from app.core.logging import get_logger
from app.db.session import engine
from app.models.finding import Finding
from app.rag.embedder import SentenceTransformerEmbedder
from app.rag.store import PgVectorKnowledgeStore
from app.services.grounding_service import GroundingService

get_logger(__name__)

DATA_FILE = Path(__file__).resolve().parent.parent / "data" / "eval" / "retrieval_queries.json"

def rag_grade(data_file: Path):
    with open(data_file, "r", encoding="utf-8") as f:
        queries = json.load(f)["queries"]

    positives = [q for q in queries if q["expected"]]
    negatives = [q for q in queries if not q["expected"]]

    embedder = SentenceTransformerEmbedder()
    hit1 = hit3 = 0

    with Session(engine) as session:
        svc = GroundingService(PgVectorKnowledgeStore(session, embedder))

        pos_scores = []
        neg_scores = []

        for q in positives:
            cited = svc.ground_message(q["query"], top_k=3)
            first_ok = bool(cited) and cited[0].source_id in q["expected"]
            in_top3 = any(c.source_id in q["expected"] for c in cited)
            hit1 += first_ok
            hit3 += in_top3
            if first_ok:
                pos_scores.append(cited[0].score)
            else:
                label = "2nd/3rd" if in_top3 else "MISS"
                print(f"{label:8} {q["query"][:60]!r} -> expected {q["expected"]}, got {cited}")

        print("\nNO-ANSWER QUESTION (should return nothing)")
        for q in negatives:
            cited = svc.ground_message(q["query"], top_k=1)
            if cited:
                neg_scores.append(cited[0].score)
                print(f"  cited {cited[0].source_id} (score {cited[0].score:.3f})  <- {q['query'][:50]!r}")

    n = len(positives)
    print("\nRAG EVALUATION")
    print(f"Right CWE ranked 1st: {hit1}/{n} {hit1 / n:.1%}")
    print(f"Right CWE in top 3: {hit3}/{n} {hit3 / n:.1%}")

    print("\nCUT-OFF OPTIONS")
    for t in [0.25, 0.30, 0.35, 0.40, 0.45, 0.50]:
        kept = sum(s >= t for s in pos_scores)
        silenced = sum(s < t for s in neg_scores)
        print(f"  cut-off {t:.2f}: correct answers kept {kept}/{len(positives)} | "
            f"no-answer questions silenced {silenced}/{len(negatives)}")

if __name__ == "__main__":
    rag_grade(DATA_FILE)

        



    

                
