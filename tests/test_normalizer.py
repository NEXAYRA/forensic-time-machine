from normalizer import normalize_event, normalize_events, normalize_event_type


def _base_record():
    return {
        "event_id": "EV-001",
        "timestamp": "2026-01-15T09:41:02+00:00",
        "event_type": "user_login",
        "source": "auth.log",
    }


def test_event_type_normalization_known_alias():
    assert normalize_event_type("user login") == "USER_LOGIN"
    assert normalize_event_type("process_start") == "PROCESS_START"


def test_event_type_normalization_unknown_type_passthrough():
    assert normalize_event_type("weird custom event") == "WEIRD_CUSTOM_EVENT"


def test_normalize_event_basic_fields():
    event = normalize_event(_base_record())
    assert event.event_id == "EV-001"
    assert event.event_type == "USER_LOGIN"
    assert event.source == "auth.log"


def test_normalize_event_optional_fields_absent_stay_none():
    event = normalize_event(_base_record())
    assert event.host is None
    assert event.actor is None
    assert event.process is None
    assert event.file_path is None
    assert event.network is None


def test_normalize_event_optional_fields_present():
    record = _base_record()
    record.update({"host": "WKSTN-07", "actor": "jdoe"})
    event = normalize_event(record)
    assert event.host == "WKSTN-07"
    assert event.actor == "jdoe"


def test_normalize_event_preserves_evidence_reference():
    record = _base_record()
    event = normalize_event(record)
    assert event.evidence_ref == "EV-001"
    assert event.raw_evidence == record


def test_normalize_event_does_not_fabricate_confidence():
    record = _base_record()
    event = normalize_event(record)
    assert event.confidence is None


def test_normalize_events_batch():
    records = [_base_record(), {**_base_record(), "event_id": "EV-002"}]
    events = normalize_events(records)
    assert len(events) == 2
    assert {e.event_id for e in events} == {"EV-001", "EV-002"}
