"""
validator.py

Validates raw forensic evidence records before they are normalized
into the common ForensicEvent model.

Validation happens on the *raw* dict form (before construction of a
ForensicEvent), so that malformed evidence can be rejected with a
clear, specific reason rather than causing a confusing exception
deep inside normalization.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List

REQUIRED_FIELDS = ("event_id", "timestamp", "event_type", "source")
VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}


@dataclass
class ValidationResult:
    """Outcome of validating a single raw evidence record."""

    is_valid: bool
    errors: List[str]
    record: Dict[str, Any]


def validate_event(record: Dict[str, Any]) -> ValidationResult:
    """
    Validate a single raw evidence record (a plain dict, as loaded
    from JSON).

    Checks:
    - All REQUIRED_FIELDS are present and non-empty.
    - 'timestamp' parses as an ISO 8601 datetime.
    - 'confidence' (if present) is a number between 0.0 and 1.0.
    - 'severity' (if present) is one of VALID_SEVERITIES.

    Returns a ValidationResult; it never raises for malformed input
    -- malformed evidence is expected and must be reported, not
    thrown away silently or crash the pipeline.
    """
    errors: List[str] = []

    for field_name in REQUIRED_FIELDS:
        value = record.get(field_name)
        if value is None or (isinstance(value, str) and not value.strip()):
            errors.append(f"Missing required field: '{field_name}'")

    timestamp = record.get("timestamp")
    if timestamp is not None:
        if isinstance(timestamp, str):
            try:
                datetime.fromisoformat(timestamp)
            except ValueError:
                errors.append(f"Invalid timestamp format: '{timestamp}'")
        elif not isinstance(timestamp, datetime):
            errors.append(f"Invalid timestamp type: {type(timestamp).__name__}")

    confidence = record.get("confidence")
    if confidence is not None:
        if not isinstance(confidence, (int, float)) or isinstance(confidence, bool):
            errors.append(f"Invalid confidence type: {type(confidence).__name__}")
        elif not (0.0 <= float(confidence) <= 1.0):
            errors.append(f"Invalid confidence value: {confidence} (must be 0.0-1.0)")

    severity = record.get("severity")
    if severity is not None and severity not in VALID_SEVERITIES:
        errors.append(
            f"Invalid severity value: '{severity}' (must be one of {sorted(VALID_SEVERITIES)})"
        )

    return ValidationResult(is_valid=not errors, errors=errors, record=record)


def validate_events(records: List[Dict[str, Any]]) -> List[ValidationResult]:
    """Validate a batch of raw evidence records."""
    return [validate_event(r) for r in records]
