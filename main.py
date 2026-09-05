"""
main.py

Phase-1 backend: intentionally minimal.

Provides:
- GET /health          -> liveness check
- GET /demo/timeline    -> runs the sample-data pipeline end-to-end
                           (validate -> normalize -> timeline ->
                           correlate -> AI interface) and returns the
                           resulting timeline + AI summary as JSON.

Explicitly NOT included (future phases): authentication, a database,
user management, or production deployment concerns. This exists so
the frontend and future integrations have a real, working shape of
the API to build against.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from fastapi import FastAPI, HTTPException

# --- Path bootstrap ---------------------------------------------------
# The project's Phase-1 modules live in hyphenated directories
# (forensic-engine/, timeline-engine/, ai-engine/), which are not
# valid Python package names. Rather than rename the directories
# (and break the target repo layout everyone agreed on), we add each
# directory directly to sys.path so its modules can be imported by
# their plain module names. See README.md "Import structure" section
# for the full explanation.
ROOT = Path(__file__).resolve().parent.parent
for module_dir in ("forensic-engine", "timeline-engine", "ai-engine"):
    path = str(ROOT / module_dir)
    if path not in sys.path:
        sys.path.insert(0, path)

from validator import validate_events  # noqa: E402
from normalizer import normalize_events  # noqa: E402
from timeline import build_timeline  # noqa: E402
from analyzer import analyze_timeline  # noqa: E402

app = FastAPI(title="NEXAYRA Phase-1 API", version="0.1.0")

SAMPLE_DATA_PATH = ROOT / "sample-data" / "events" / "sample_events.json"


@app.get("/health")
def health() -> dict:
    """Basic liveness check."""
    return {"status": "ok", "service": "nexayra-phase1"}


@app.get("/demo/timeline")
def demo_timeline() -> dict:
    """
    Run the full Phase-1 pipeline against the bundled synthetic
    sample data and return the resulting timeline + AI summary.
    """
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
