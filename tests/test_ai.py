from datetime import datetime, timezone

from event_schema import ForensicEvent, Timeline
from timeline import build_timeline
from analyzer import analyze_timeline


def _event(event_id, minute, **kwargs):
    return ForensicEvent(
        event_id=event_id,
        timestamp=datetime(2026, 1, 15, 9, 41, minute, tzinfo=timezone.utc),
        event_type="TEST_EVENT",
        source="test",
        **kwargs,
    )


def test_empty_timeline():
    summary = analyze_timeline(Timeline(events=[], correlations=[]))
    assert summary.event_count == 0
    assert summary.correlation_count == 0
    assert summary.requires_investigator_review is True


def test_timeline_with_events_produces_findings():
    events = [_event("EV-001", 2), _event("EV-002", 18, host="WKSTN-07")]
    events[0].host = "WKSTN-07"
    timeline = build_timeline(events)
    summary = analyze_timeline(timeline)
    assert summary.event_count == 2
    assert len(summary.findings) >= 1
    valid_ids = {e.event_id for e in timeline.events}
    for finding in summary.findings:
        for eid in finding.supporting_event_ids:
            assert eid in valid_ids


def test_investigator_review_always_required():
    events = [_event("EV-001", 2)]
    timeline = build_timeline(events)
    summary = analyze_timeline(timeline)
    assert summary.requires_investigator_review is True
