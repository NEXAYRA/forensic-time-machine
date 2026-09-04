"""
timeline.py

Builds a chronologically ordered Timeline from a list of normalized
ForensicEvent objects.

Design notes
------------
- Ordering is a stable sort on (timestamp, event_id). The event_id
  tiebreaker gives deterministic, reproducible output when multiple
  events share the exact same timestamp, which is common with
  coarse-grained log sources.
- This module does not validate or normalize events -- that is the
  forensic-engine's job. The Timeline Engine trusts that whatever it
  receives is already a well-formed ForensicEvent, and focuses only
  on ordering + correlation.
"""

from __future__ import annotations

from typing import List

from event_schema import ForensicEvent, Timeline
from correlation import correlate_events


def build_timeline(events: List[ForensicEvent]) -> Timeline:
    """
    Build a chronologically ordered Timeline from forensic events.

    Handles:
    - Empty input (returns an empty Timeline, not an error).
    - Events sharing an identical timestamp (broken by event_id so
      ordering is deterministic across runs).

    Correlation is computed automatically using the default
    correlation rules; see correlation.py for details.
    """
    if not events:
        return Timeline(events=[], correlations=[])

    ordered = sorted(events, key=lambda e: (e.timestamp, e.event_id))
    correlations = correlate_events(ordered)
    return Timeline(events=ordered, correlations=correlations)
