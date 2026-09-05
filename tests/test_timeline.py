from datetime import datetime, timezone

from event_schema import ForensicEvent
from timeline import build_timeline


def _event(event_id, minute, **kwargs):
    return ForensicEvent(
        event_id=event_id,
        timestamp=datetime(2026, 1, 15, 9, 41, minute, tzinfo=timezone.utc),
        event_type="TEST_EVENT",
        source="test",
        **kwargs,
    )


def test_chronological_ordering():
    events = [_event("EV-003", 23), _event("EV-001", 2), _event("EV-004", 31), _event("EV-002", 18)]
    timeline = build_timeline(events)
    assert [e.event_id for e in timeline.events] == ["EV-001", "EV-002", "EV-003", "EV-004"]


def test_empty_input():
    timeline = build_timeline([])
    assert timeline.events == []
    assert timeline.correlations == []


def test_same_timestamp_deterministic_order():
    a = _event("EV-002", 10)
    b = _event("EV-001", 10)
    timeline = build_timeline([a, b])
    assert [e.event_id for e in timeline.events] == ["EV-001", "EV-002"]


def test_event_id_preservation():
    events = [_event("EV-001", 5), _event("EV-002", 6)]
    timeline = build_timeline(events)
    ids = {e.event_id for e in timeline.events}
    assert ids == {"EV-001", "EV-002"}


def test_evidence_reference_preserved_through_timeline():
    event = _event("EV-001", 5, evidence_ref="EV-001")
    timeline = build_timeline([event])
    assert timeline.events[0].evidence_ref == "EV-001"
