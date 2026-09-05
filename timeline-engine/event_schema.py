from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}


@dataclass
class ForensicEvent:
    event_id: str
    timestamp: datetime
    event_type: str
    source: str

    host: Optional[str] = None
    actor: Optional[str] = None
    process: Optional[str] = None
    file_path: Optional[str] = None
    parent_process_id: Optional[str] = None
    network: Optional[Dict[str, Any]] = None

    confidence: Optional[float] = None
    severity: Optional[str] = None

    evidence_ref: Optional[str] = None
    raw_evidence: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.event_id:
            raise ValueError("ForensicEvent requires a non-empty event_id")
        if not isinstance(self.timestamp, datetime):
            raise ValueError("ForensicEvent.timestamp must be a datetime")
        if self.timestamp.tzinfo is None:
            self.timestamp = self.timestamp.replace(tzinfo=timezone.utc)
        if not self.event_type:
            raise ValueError("ForensicEvent requires a non-empty event_type")
        if not self.source:
            raise ValueError("ForensicEvent requires a non-empty source")
        if self.severity is not None and self.severity not in VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity '{self.severity}', must be one of {sorted(VALID_SEVERITIES)}"
            )
        if self.confidence is not None and not (0.0 <= self.confidence <= 1.0):
            raise ValueError("ForensicEvent.confidence must be between 0.0 and 1.0")

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        return data

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "ForensicEvent":
        payload = dict(data)
        ts = payload.get("timestamp")
        if isinstance(ts, str):
            payload["timestamp"] = datetime.fromisoformat(ts)
        return ForensicEvent(**payload)


@dataclass
class CorrelationLink:
    event_id_a: str
    event_id_b: str
    reason: str
    rule: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Timeline:
    events: List[ForensicEvent] = field(default_factory=list)
    correlations: List[CorrelationLink] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "events": [e.to_dict() for e in self.events],
            "correlations": [c.to_dict() for c in self.correlations],
        }
