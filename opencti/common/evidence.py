from uuid import NAMESPACE_URL, uuid5

from stix2 import Note, Relationship


def stable_id(kind, key):
    return f"{kind}--{uuid5(NAMESPACE_URL, 'vysion:' + key)}"


def evidence_note(source, record_id, target, title, content, markings=(), references=()):
    """Evidence is not an IOC: record a cited note without asserting maliciousness."""
    return Note(
        id=stable_id("note", f"{source}:{record_id}:{target}"),
        abstract=title[:200], content=content, object_refs=[target],
        labels=["vysion", f"vysion:{source}"],
        object_marking_refs=list(markings), external_references=list(references),
        allow_custom=True,
    )


def relation(source, target, kind="related-to", markings=()):
    return Relationship(
        id=stable_id("relationship", f"{source}:{kind}:{target}"),
        source_ref=source, target_ref=target, relationship_type=kind,
        object_marking_refs=list(markings), allow_custom=True,
    )
