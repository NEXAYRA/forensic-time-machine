import json
from pathlib import Path

from validator import validate_events
from normalizer import normalize_events
from timeline import build_timeline
from analyzer import analyze_timeline

SAMPLE_DATA_PATH = (
    Path(__file__).resolve().parent.parent / "sample-data" / "events" / "sample_events.json"
)


def _load_sample_events():
    with open(SAMPLE_DATA_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def test_full_pipeline_end_to_end():
    raw_records = _load_sample_events()
    assert len(raw_records) == 4

    validation_results = validate_events(raw_records)
    assert all(r.is_valid for r in validation_results), [
        r.errors for r in validation_results if not r.is_valid
    ]
    valid_records = [r.record for r in validation_results]

    normalized_events = normalize_events(valid_records)
    assert len(normalized_events) == 4
    for event in normalized_events:
        assert event.evidence_ref is not None
        assert event.raw_evidence is not None

    timeline = build_timeline(normalized_events)
    ordered_ids = [e.event_id for e in timeline.events]
    assert ordered_ids == ["EV-001", "EV-002", "EV-003", "EV-004"]

    rules_seen = {link.rule for link in timeline.correlations}
    assert "same_host" in rules_seen
    assert "same_actor" in rules_seen
    assert "parent_child_process" in rules_seen

    summary = analyze_timeline(timeline)
    assert summary.event_count == 4
    assert summary.correlation_count == len(timeline.correlations)
    assert summary.requires_investigator_review is True

    valid_ids = set(ordered_ids)
    for finding in summary.findings:
        for eid in finding.supporting_event_ids:
            assert eid in valid_ids
