from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# Map known aliases to canonical event type names.
# Unknown event types pass through unchanged.
EVENT_TYPE_ALIASES = {
    "login": "authentication",
    "signin": "authentication",
    "logon": "authentication",
    "file_write": "file_modification",
    "file_change": "file_modification",
    "proc_start": "process_execution",
    "process_start": "process_execution",
    "net_conn": "network_connection",
    "netconn": "network_connection",
}

OPTIONAL_FIELDS = ("confidence", "severity", "actor", "host", "process", "file", "evidence_reference")


@dataclass
class NormalizedEvent:
    event_id: str
    timestamp: str
    event_type: str
    source: str
    confidence: Optional[float] = None
    severity: Optional[str] = None
    actor: Optional[str] = None
    host: Optional[str] = None
    process: Optional[str] = None
    file: Optional[str] = None
    evidence_reference: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)


def normalize_event_type(event_type: Optional[str]) -> Optional[str]:
    if event_type is None:
        return None
    key = event_type.strip().lower()
    return EVENT_TYPE_ALIASES.get(key, event_type)


def normalize_event(record: Dict[str, Any]) -> NormalizedEvent:
    event_id = record.get("event_id")
    timestamp = record.get("timestamp")
    event_type = normalize_event_type(record.get("event_type"))
    source = record.get("source")

    normalized = NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        event_type=event_type,
        source=source,
        raw=record,
    )

    # Only carry over optional fields if explicitly present.
    # Never fabricate a value (e.g. confidence) that wasn't in the input.
    for field_name in OPTIONAL_FIELDS:
        if field_name in record and record[field_name] is not None:
            setattr(normalized, field_name, record[field_name])

    return normalized


def normalize_events(records: List[Dict[str, Any]]) -> List[NormalizedEvent]:
    return [normalize_event(r) for r in records]
