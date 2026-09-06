from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass(frozen=True)
class RawEvidence:
    evidence_id: str
    payload: Dict[str, Any] = field(default_factory=dict)
    source: str = "unknown"

    def get(self, key: str, default: Any = None) -> Any:
        return self.payload.get(key, default)


def load_raw_evidence(records: list, default_source: str = "sample-data") -> list:
    evidence_items = []
    for record in records:
        evidence_id = record.get("event_id")
        if not evidence_id:
            continue
        evidence_items.append(
            RawEvidence(
                evidence_id=evidence_id,
                payload=dict(record),
                source=record.get("source", default_source),
            )
        )
    return evidence_items
