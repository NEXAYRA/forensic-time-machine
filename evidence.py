"""
evidence.py

Represents a single piece of raw, unmodified forensic evidence
before it enters validation/normalization.

SECURITY / INTEGRITY NOTE:
Evidence is never executed, parsed as code, or mutated in place.
RawEvidence.payload is treated as untrusted, opaque data for the
entire lifetime of the object. Anything derived from it (a
ForensicEvent) is a *separate* object; the original is preserved
so an investigator can always trace a normalized event back to
exactly what was originally collected.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass(frozen=True)
class RawEvidence:
    """
    An immutable wrapper around one raw evidence record.

    evidence_id:
        Unique identifier for this evidence record (used as the
        provenance reference on the derived ForensicEvent).
    payload:
        The original, untouched evidence data as loaded from the
        source (e.g. a dict parsed from JSON). Never mutated.
    source:
        Where this evidence came from (file name, collection tool,
        log source, etc.).
    """

    evidence_id: str
    payload: Dict[str, Any] = field(default_factory=dict)
    source: str = "unknown"

    def get(self, key: str, default: Any = None) -> Any:
        """Read-only accessor into the raw payload."""
        return self.payload.get(key, default)


def load_raw_evidence(records: list, default_source: str = "sample-data") -> list:
    """
    Wrap a list of raw evidence dicts (e.g. loaded from JSON) into
    RawEvidence objects.

    Each record must contain an 'event_id' (used as the evidence_id)
    so provenance can be tracked. Records missing an id are skipped
    with no attempt to invent one -- forensic provenance must be
    real, not guessed.
    """
    evidence_items = []
    for record in records:
        evidence_id = record.get("event_id")
        if not evidence_id:
            # No fabricated IDs: an evidence record without an
            # identifiable id cannot be tracked, so it is excluded
            # rather than silently assigned one.
            continue
        evidence_items.append(
            RawEvidence(
                evidence_id=evidence_id,
                payload=dict(record),
                source=record.get("source", default_source),
            )
        )
    return evidence_items
