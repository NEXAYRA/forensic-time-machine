from datetime import datetime, timedelta, timezone

from event_schema import ForensicEvent
from correlation import correlate_events


def _event(event_id, offset_minutes=0, **kwargs):
    base = datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc)
    return ForensicEvent(
        event_id=event_id,
        timestamp=base + timedelta(minutes=offset_minutes),
        event_type="TEST_EVENT",
        source="test",
        **kwargs,
    )


def _rules_for(links, a, b):
    return {
        link.rule
        for link in links
        if {link.event_id_a, link.event_id_b} == {a, b}
    }


def test_same_host_correlation():
    a = _event("EV-001", host="WKSTN-07")
    b = _event("EV-002", 1, host="WKSTN-07")
    links = correlate_events([a, b])
    assert "same_host" in _rules_for(links, "EV-001", "EV-002")


def test_same_actor_correlation():
    a = _event("EV-001", actor="jdoe")
    b = _event("EV-002", 1, actor="jdoe")
    links = correlate_events([a, b])
    assert "same_actor" in _rules_for(links, "EV-001", "EV-002")


def test_same_process_correlation():
    a = _event("EV-001", process="powershell.exe")
    b = _event("EV-002", 1, process="powershell.exe")
    links = correlate_events([a, b])
    assert "same_process" in _rules_for(links, "EV-001", "EV-002")


def test_same_file_correlation():
    a = _event("EV-001", file_path="C:\\temp\\payload.tmp")
    b = _event("EV-002", 1, file_path="C:\\temp\\payload.tmp")
    links = correlate_events([a, b])
    assert "same_file" in _rules_for(links, "EV-001", "EV-002")


def test_unrelated_events_no_correlation():
    a = _event("EV-001", 0, host="HOST-A", actor="alice", process="proc-a", file_path="a.txt")
    b = _event("EV-002", 60, host="HOST-B", actor="bob", process="proc-b", file_path="b.txt")
    links = correlate_events([a, b])
    assert _rules_for(links, "EV-001", "EV-002") == set()


def test_correlation_is_not_causation_semantics():
    a = _event("EV-001", host="WKSTN-07")
    b = _event("EV-002", 1, host="WKSTN-07")
    links = correlate_events([a, b])
    for link in links:
        lowered = link.reason.lower()
        assert "caused" not in lowered
        assert "confirmed malicious" not in lowered
