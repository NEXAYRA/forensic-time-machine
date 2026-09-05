from __future__ import annotations

import json
import sys
from pathlib import Path

from fastapi import FastAPI, HTTPException

ROOT = Path(__file__).resolve().parent.parent
for module_dir in ("forensic-engine", "timeline-engine", "ai-engine"):
    path = str(ROOT / module_dir)
    if path not in sys.path:
        sys.path.insert(0, path)

from validator import validate_events
from normalizer import normalize_events
from timeline import build_timeline
from analyzer import analyze_timeline

app = FastAPI(title="NEXAYRA Phase-1 API", version="0.1.0")

SAMPLE_DATA_PATH = ROOT / "sample-data" / "events" / "sample_events.json"


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "nexayra-phase1"}


@app.get("/demo/timeline")
def demo_timeline() -> dict:
    if not SAMPLE_DATA_PATH.exists():
        raise HTTPException(status_code=500, detail="Sample data not found")

    with open(SAMPLE_DATA_PATH, "r", encoding="utf-8") as f:
        raw_records = json.load(f)

    validation_results = validate_events(raw_records)
    valid_records = [r.record for r in validation_results if r.is_valid]
    invalid_count = len(validation_results) - len(valid_records)

    normalized_events = normalize_events(valid_records)
    timeline = build_timeline(normalized_events)
    summary = analyze_timeline(timeline)

    return {
        "invalid_event_count": invalid_count,
        "timeline": timeline.to_dict(),
        "ai_summary": summary.to_dict(),
    }
