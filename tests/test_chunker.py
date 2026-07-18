from app.rag.chunker import Section, chunk_document, _split_with_overlap

def _doc(sections):
    return chunk_document(
        source="cwe",
        source_id="CWE-89",
        title="SQL Injection",
        url="https://cwe.mitre.org/data/definitions/89.html",
        sections=sections,
        target_words=10,
        overlap_words=3,
        min_words=2
    )

def test_short_section_becomes_one_chunk():
    chunks = _doc([Section("Description", "SQL injection happens here")])
    assert len(chunks) == 1
    assert chunks[0].source_id == "CWE-89"
    assert chunks[0].section == "Description"
    assert "SQL injection" in chunks[0].content

def test_long_section_splits_with_overlap():
    text = " ".join(f"w{i}" for i in range(25))
    chunks = _doc([Section("Body", text)])
    assert len(chunks) > 1
    first_words = chunks[0].content.split()
    second_words = chunks[1].content.split()
    assert first_words[-3:] == second_words[:3]

def test_metadata_is_preserved_on_every_chunk():
    chunks = _doc([Section("A", " ".join(f"w{i}" for i in range(40)))])
    assert all(c.title == "SQL Injection" for c in chunks)
    assert all(c.url.endswith("89.html") for c in chunks)

def test_tiny_fragments_are_dropped():
    chunks = _doc([Section("Heading", "x")])
    assert chunks == []

def test_overlap_must_be_smaller_than_target():
    try:
        _split_with_overlap(["a", "b", "c"], target_words=3, overlap_words=3)
    except ValueError:
        return
    raise AssertionError("expected ValueError when overlap >= target")
