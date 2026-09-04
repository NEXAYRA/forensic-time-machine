"""
event_schema.py

Defines the common forensic event model used across the whole
NEXAYRA pipeline (forensic-engine -> timeline-engine -> ai-engine).

Every module that produces or consumes forensic events should use
this dataclass instead of passing around raw dictionaries, so that
the shape of an "event" is defined in exactly one place.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# Confidence and severity are kept as bounded numeric/enumerated
# values so downstream modules (AI engine, frontend) can rely on
# a predictable range rather than free-text strings.
VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}


@dataclass
class ForensicEvent:
    """
    The common forensic event model (Phase 1).

    Fields
    ------
    event_id:
        Stable, unique identifier for the event (e.g. "EV-001").
    timestamp:
        Timezone-aware UTC datetime the event occurred at.
    event_type:
        Normalized event type, e.g. "USER_LOGIN", "PROCESS_START".
    source:
        Where the raw evidence came from (e.g. "auth.log",
        "edr_agent", "browser_history").
    host:
        Hostname or asset identifier the event occurred on, if known.
    actor:
        User or account associated with the event, if known.
    process:
        Process name/identifier associated with the event, if known.
    file_path:
        File or object path associated with the event, if known.
    parent_process_id:
        Identifier of the parent process, if the event is a process
        and lineage information is available.
    network:
        Free-form dict for related network information
        (e.g. {"src_ip": ..., "dst_ip": ..., "dst_port": ...}).
        Left as None when not applicable/unavailable.
    confidence:
        0.0-1.0 confidence that the *evidence itself* is accurate.
        This is NOT a statement about attacker intent.
    severity:
        One of VALID_SEVERITIES. Represents the forensic significance
        of the raw event, not a legal or causal judgement.
    evidence_ref:
        Reference back to the original, unmodified evidence record
        this event was derived from (id, file, or hash). Required for
        provenance -- Phase 1 must never lose track of where a
        normalized event came from.
    raw_evidence:
        The untouched original evidence payload, preserved verbatim
        for provenance. Normalization must never mutate this.
    metadata:
        Any additional normalized fields that don't fit the schema
        above, kept as a dict so the model can evolve without
        breaking existing consumers.
    """

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
            # Normalize naive datetimes to UTC rather than silently
            # guessing -- Phase 1 forensic timestamps must be explicit.
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
        """Serialize the event to a JSON-friendly dict."""
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        return data

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "ForensicEvent":
        """Construct a ForensicEvent from a plain dict (e.g. loaded JSON)."""
        payload = dict(data)
        ts = payload.get("timestamp")
        if isinstance(ts, str):
            payload["timestamp"] = datetime.fromisoformat(ts)
        return ForensicEvent(**payload)


@dataclass
class CorrelationLink:
    """
    Represents a *potential* relationship between two events.

    IMPORTANT: a CorrelationLink means "these events are potentially
    related" based on a named, explainable rule. It never means
    "event A caused event B" and never means "confirmed malicious".
    Causal/forensic conclusions are for a human investigator (and,
    later, investigator-reviewed AI assistance) to make.
    """

    event_id_a: str
    event_id_b: str
    reason: str
    rule: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Timeline:
    """
    An ordered, correlated collection of forensic events.

    A Timeline never claims to be a complete or admissible legal
    record -- it is Phase-1 investigative scaffolding built from
    whatever evidence was supplied.
    """

    events: List[ForensicEvent] = field(default_factory=list)
    correlations: List[CorrelationLink] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "events": [e.to_dict() for e in self.events],
            "correlations": [c.to_dict() for c in self.correlations],
        }
