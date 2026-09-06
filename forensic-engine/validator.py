from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from event_schema import ForensicEvent

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
    key = raw_type.strip().lower()
    return EVENT_TYPE_ALIASES.get(key, raw_type.strip().upper().replace(" ", "_"))


def normalize_event(record: Dict[str, Any]) -> ForensicEvent:
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
    return [normalize_event(r) for r in records]


def _as_float_or_none(value: Any) -> Optional[float]:
    if value is None:
        return None
    return float(value)
