"""
Chunking: split the knowledge documento into small, retrivable pieces.

Why chunking is the underrated skill: has to be neither big (cover many ideas) or small (shred the context)

The strategy is `section-aware with a token budget and overlap`:
 - Every section of a document is chunked independently, so a chunk never mixes unrelated sections.
 - Long sections get splited on a target size with a small overlap, so a sentence cut at a boundry still
 partly appears in both neighbours and retrievel doesn't miss it.

 Token counting: approximate tokens by whitespaces words (~1.3 tokens/word for English).
 """

from dataclasses import dataclass
from app.rag.port import Chunk

@dataclass(frozen=True)
class Section:
    """A titles span of a source document, produced by ingestation parser"""
    heading: str | None
    text: str

def _split_with_overlap(
    words: list[str],
    target_words: int,
    overlap_words: int
) -> list[str]:
    """
    Slide a window of `target_words` across `words`, stepping forward by
    (target_words - overlap_words) each time so consecutive windows overlap
    """
    if target_words <= 0:
        raise ValueError("target_words must be > 0")
    if overlap_words >= target_words:
        raise ValueError("overlap_words must be smaller than target_words")
    
    step = target_words - overlap_words
    pieces: list[str] = []
    for start in range(0, len(words), step):
        window = words[start:start + target_words]
        if not window:
            break
        pieces.append(" ".join(window))
        if start + target_words >= len(words):
            break
    return pieces

def chunk_document(
    *,
    source: str,
    source_id: str,
    title: str,
    url: str,
    sections: list[Section],
    target_words: int = 180,
    overlap_words: int = 30,
    min_words: int = 12,
) -> list[Chunk]:
    """
    Turn a parsed document into a list of Chunks ready to embed:
    - target_words ~180 (~230 tokens) keeps each chunk focused but self-contained.
    - overlap_words ~30 preserves context across boundaries.
    - min_words drops tiny fragments (e.g. a lone heading) that add noise.
    """
    chunks: list[Chunk] = []

    for section in sections:
        text = section.text.strip()
        if not text:
            continue

        words = text.split()
        pieces = _split_with_overlap(words, target_words, overlap_words)

        for piece in pieces:
            if len(piece.split()) < min_words:
                continue
            chunks.append(
                Chunk(
                    source=source,
                    source_id=source_id,
                    title=title,
                    url=url,
                    section=section.heading,
                    content=piece
                )
            )
    
    return chunks
