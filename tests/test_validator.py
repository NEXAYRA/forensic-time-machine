from validator import validate_event, validate_events


def _base_event():
    return {
        "event_id": "EV-001",
        "timestamp": "2026-01-15T09:41:02+00:00",
        "event_type": "user_login",
        "source": "auth.log",
        "confidence": 0.9,
        "severity": "low",
    }


def test_valid_event_passes():
    result = validate_event(_base_event())
    assert result.is_valid
    assert result.errors == []


def test_missing_event_id():
    record = _base_event()
    del record["event_id"]
    result = validate_event(record)
    assert not result.is_valid
    assert any("event_id" in e for e in result.errors)


def test_missing_timestamp():
    record = _base_event()
    del record["timestamp"]
    result = validate_event(record)
    assert not result.is_valid
    assert any("timestamp" in e for e in result.errors)


def test_missing_event_type():
    record = _base_event()
    del record["event_type"]
    result = validate_event(record)
    assert not result.is_valid
    assert any("event_type" in e for e in result.errors)


def test_missing_source():
    record = _base_event()
    del record["source"]
    result = validate_event(record)
    assert not result.is_valid
    assert any("source" in e for e in result.errors)


def test_valid_timestamp_formats():
    record = _base_event()
    record["timestamp"] = "2026-01-15T09:41:02"
    result = validate_event(record)
    assert result.is_valid


def test_invalid_timestamp():
    record = _base_event()
    record["timestamp"] = "not-a-date"
    result = validate_event(record)
    assert not result.is_valid
    assert any("timestamp" in e for e in result.errors)


def test_valid_confidence():
    record = _base_event()
    record["confidence"] = 0.5
    result = validate_event(record)
    assert result.is_valid


def test_invalid_confidence_out_of_range():
    record = _base_event()
    record["confidence"] = 1.5
    result = validate_event(record)
    assert not result.is_valid
    assert any("confidence" in e for e in result.errors)


def test_invalid_confidence_type():
    record = _base_event()
    record["confidence"] = "high"
    result = validate_event(record)
    assert not result.is_valid
    assert any("confidence" in e for e in result.errors)


def test_valid_severity():
    record = _base_event()
    record["severity"] = "critical"
    result = validate_event(record)
    assert result.is_valid


def test_invalid_severity():
    record = _base_event()
    record["severity"] = "catastrophic"
    result = validate_event(record)
    assert not result.is_valid
    assert any("severity" in e for e in result.errors)


def test_validate_events_batch():
    records = [_base_event(), {"event_id": "EV-002"}]
    results = validate_events(records)
    assert len(results) == 2
    assert results[0].is_valid
    assert not results[1].is_valid
