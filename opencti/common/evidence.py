from uuid import NAMESPACE_URL, uuid5

import json

from pycti import Identity as OpenCTIIdentity
from stix2 import Bundle, Identity, Note, ObservedData, Relationship


VYSION_AUTHOR = Identity(
    id=OpenCTIIdentity.generate_id("Vysion", "organization"),
    name="Vysion", identity_class="organization",
    description="Provider of Vysion intelligence.",
)


def evidence_bundle(objects):
    """Attribute connector-generated objects without altering their STIX IDs.

    OpenCTI uses a custom author reference for cyber observables. Only generated
    objects belong here: never reattribute the analyst's enrichment input.
    """
    authored = [VYSION_AUTHOR]
    for obj in objects:
        if obj.id == VYSION_AUTHOR.id:
            continue
        data = json.loads(obj.serialize())
        field = "x_opencti_created_by_ref" if obj.type in {"cryptocurrency-wallet", "url"} else "created_by_ref"
        data[field] = VYSION_AUTHOR.id
        authored.append(data)
    return Bundle(objects=authored, allow_custom=True).serialize()


def stable_id(kind, key):
    return f"{kind}--{uuid5(NAMESPACE_URL, 'vysion:' + key)}"


def evidence_note(source, record_id, target, title, content, markings=(), references=(), object_refs=None):
    """Evidence is not an IOC: record a cited note without asserting maliciousness."""
    return Note(
        id=stable_id("note", f"{source}:{record_id}:{target}"),
        abstract=title[:200], content=content, object_refs=object_refs or [target],
        labels=["vysion", f"vysion:{source}"],
        object_marking_refs=list(markings), external_references=list(references),
        allow_custom=True,
    )


def evidence_observed_data_id(target):
    """Return the OpenCTI-stable evidence timeline ID for an enrichment target."""
    return stable_id("observed-data", f"enrichment:{target}")


def evidence_observed_data(target, first_observed, last_observed, number_observed,
                           sources=(), markings=(), references=()):
    """Record a dated source-observation timeline without asserting ownership.

    OpenCTI consolidates Observed Data that point to the same observable. Model
    that behaviour deliberately with one timeline per enrichment target rather
    than submitting one nominal object per capture and relying on a merge.
    """
    return ObservedData(
        id=evidence_observed_data_id(target),
        first_observed=first_observed,
        last_observed=last_observed,
        number_observed=number_observed,
        object_refs=[target],
        labels=["vysion", "vysion:evidence", *(f"vysion:{source}" for source in sorted(set(sources)))],
        object_marking_refs=list(markings),
        external_references=list(references),
        x_vysion_evidence_sources=sorted(set(sources)),
        allow_custom=True,
    )


def relation(source, target, kind="related-to", markings=()):
    return Relationship(
        id=stable_id("relationship", f"{source}:{kind}:{target}"),
        source_ref=source, target_ref=target, relationship_type=kind,
        object_marking_refs=list(markings), allow_custom=True,
    )
