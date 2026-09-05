"""
normalizer.py

Normalizes *validated* raw evidence records into the common
ForensicEvent model (defined in timeline-engine/event_schema.py).

Rules (non-negotiable for forensic integrity):
- Normalization never invents missing information. If a field is
  not present in the raw evidence, the ForensicEvent field is left
  as None -- never guessed or defaulted to something misleading.
- The original raw evidence is preserved verbatim on the resulting
  ForensicEvent (raw_evidence) and referenced by id (evidence_ref),
  so derived/normalized data is always traceable back to its source.
- Only records that passed validation should be passed in here;
  this module does not re-validate.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from event_schema import ForensicEvent

# Maps common raw event-type spellings/casings onto a single
# canonical uppercase form. Unknown types are passed through
# uppercased rather than rejected, so normalization degrades
# gracefully instead of dropping unfamiliar-but-valid evidence.
EVENT_TYPE_ALIASES = {
    "login": "USER_LOGIN",
    "user login": "USER_LOGIN",
    "user_login": "USER_LOGIN",
    "logout": "USER_LOGOUT",
    "user_logout": "USER_LOGOUT",
    "process start": "PROCESS_START",
    "process_start": "PROCESS_START",
    "process launch": "PROCESS_START",
    "script execution": "SCRIPT_EXECUTION",
    "script_execution": "SCRIPT_EXECUTION",
    "file create": "FILE_CREATE",
    "file_create": "FILE_CREATE",
    "file created": "FILE_CREATE",
    "file modify": "FILE_MODIFY",
    "file_modify": "FILE_MODIFY",
    "network connection": "NETWORK_CONNECTION",
    "network_connection": "NETWORK_CONNECTION",
}


def normalize_event_type(raw_type: str) -> str:
    """Normalize an event type string to its canonical form."""
    key = raw_type.strip().lower()
    return EVENT_TYPE_ALIASES.get(key, raw_type.strip().upper().replace(" ", "_"))


def normalize_event(record: Dict[str, Any]) -> ForensicEvent:
    """
    Normalize a single validated raw evidence record into a
    ForensicEvent.

    Only fields actually present in `record` are populated; anything
    absent stays None on the resulting ForensicEvent rather than
    being fabricated.
    """
    timestamp = record["timestamp"]
    if isinstance(timestamp, str):
        timestamp = datetime.fromisoformat(timestamp)

    event_id = record["event_id"]

    return ForensicEvent(
        event_id=event_id,
        timestamp=timestamp,
        event_type=normalize_event_type(record["event_type"]),
        source=record["source"],
        host=record.get("host"),
        actor=record.get("actor"),
        process=record.get("process"),
        file_path=record.get("file_path"),
        parent_process_id=record.get("parent_process_id"),
        network=record.get("network"),
        confidence=_as_float_or_none(record.get("confidence")),
        severity=record.get("severity"),
        evidence_ref=event_id,
        raw_evidence=dict(record),
        metadata=record.get("metadata", {}) or {},
    )


def normalize_events(records: List[Dict[str, Any]]) -> List[ForensicEvent]:
    """Normalize a batch of already-validated raw evidence records."""
    return [normalize_event(r) for r in records]


def _as_float_or_none(value: Any) -> Optional[float]:
    if value is None:
        return None
    return float(value)
