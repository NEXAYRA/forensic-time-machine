from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List

REQUIRED_FIELDS = ("event_id", "timestamp", "event_type", "source")
VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}


@dataclass
class ValidationResult:
    is_valid: bool
    errors: List[str]
    record: Dict[str, Any]


def validate_event(record: Dict[str, Any]) -> ValidationResult:
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
    return [validate_event(r) for r in records]
