from pathlib import Path

from routerops.knowledge import KnowledgeLoader


def test_knowledge_hash_and_applicability():
    loader = KnowledgeLoader(Path("knowledge"))
    documents = loader.load()
    assert documents
    applicable = loader.applicable("QWRT R26.1.1")
    assert applicable
    assert "Not validated against QWRT R26.1.1" in applicable[0].limitations

