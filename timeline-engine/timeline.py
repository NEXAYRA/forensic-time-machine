from __future__ import annotations

from typing import List

from event_schema import ForensicEvent, Timeline
from correlation import correlate_events


def build_timeline(events: List[ForensicEvent]) -> Timeline:
    if not events:
        return Timeline(events=[], correlations=[])

    ordered = sorted(events, key=lambda e: (e.timestamp, e.event_id))
    correlations = correlate_events(ordered)
    return Timeline(events=ordered, correlations=correlations)
