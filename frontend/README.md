# Frontend — Phase 1

Phase 1 does not include a full dashboard, authentication, incident
graph, or replay engine. Those are Phase-2+ scope.

## What exists right now

`index.html` — a single static file, no build step, no framework,
no server required. Open it directly in a browser. It renders the
Phase-1 pipeline's actual output (from `sample-data/events/
demo_output.json`) as a table: one row per event, with timestamp,
type, severity, and the related events found by the correlation
engine, each tagged with the rule that linked them (`same_host`,
`same_actor`, `parent_child_process`, etc.) — never a claim of cause.

The JSON is currently embedded directly in the page as a constant
(`DEMO_DATA`) rather than fetched, so it works with zero setup. When
the FastAPI backend is running (Phase 2+), replace that constant with
a `fetch('/demo/timeline')` call — the response shape is already
identical, so none of the rendering code needs to change.

## What Phase 1 needs from the frontend

A minimal visualization layer that can conceptually render the data
already produced by the backend's `/demo/timeline` endpoint
(`backend/main.py`), which returns:

```json
{
  "timeline": {
    "events": [
      {
        "event_id": "EV-001",
        "timestamp": "2026-01-01T09:41:02+00:00",
        "event_type": "USER_LOGIN",
        "severity": "low",
        "host": "WKSTN-07",
        "actor": "jdoe",
        "...": "..."
      }
    ],
    "correlations": [
      {
        "event_id_a": "EV-001",
        "event_id_b": "EV-002",
        "rule": "same_actor",
        "reason": "Both events involve actor/user 'jdoe'."
      }
    ]
  },
  "ai_summary": { "...": "..." }
}
```

## Minimal Phase-1 UI concept

A single scrollable list/table view showing, per event:

- Timestamp
- Event type
- Severity
- Related events (from `correlations`, matched by `event_id`)

No auth, no charts, no animations, no incident graph. A static
React component reading a JSON payload and rendering a table is
sufficient to prove the concept for Phase 1.

## Future phases

- Interactive timeline visualization (zoom/pan)
- Incident graph view
- Full investigator dashboard with authentication
- Replay engine UI
- Reporting/export UI

## Tech stack (planned)

React + TypeScript + Tailwind CSS, consuming the FastAPI backend in
`backend/main.py`. Not implemented in Phase 1 beyond this concept
description.
