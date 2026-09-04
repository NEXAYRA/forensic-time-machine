"""
correlation.py

Basic, explainable correlation between forensic events.

CRITICAL SEMANTIC RULE (do not violate in future phases either):

    Correlation means "potentially related".
    Correlation does NOT mean "caused by".
    Correlation does NOT mean "confirmed malicious".

Every CorrelationLink carries a `rule` (a short machine-readable
name) and a `reason` (a human-readable explanation), so an
investigator -- or the AI engine -- can always see *why* two events
were linked and judge that reasoning for themselves.
"""

from __future__ import annotations

from datetime import timedelta
from itertools import combinations
from typing import List

from event_schema import ForensicEvent, CorrelationLink

# Events within this window of each other are considered "temporally
# proximate" for correlation purposes. Kept conservative for Phase 1.
TEMPORAL_PROXIMITY_WINDOW = timedelta(minutes=5)


def correlate_events(events: List[ForensicEvent]) -> List[CorrelationLink]:
    """
    Compute basic correlation links between events.

    Rules applied (each produces its own CorrelationLink so multiple
    rules can independently link the same pair of events):

    - same_host: events occurred on the same host/asset.
    - same_actor: events involve the same user/account.
    - same_process: events involve the same process name/identifier.
    - same_file: events involve the same file/object path.
    - related_network: events share overlapping network information.
    - parent_child_process: one event's process is the recorded
      parent of another event's process.
    - temporal_proximity: events occurred within
      TEMPORAL_PROXIMITY_WINDOW of each other (only applied when no
      stronger rule already links the pair, to avoid noisy output).

    Correlation is O(n^2) over the event list, which is acceptable
    for Phase-1 synthetic datasets. Later phases should replace this
    with indexed lookups if event volume grows significantly.
    """
    links: List[CorrelationLink] = []
    linked_pairs = set()

    for a, b in combinations(events, 2):
        pair_links = _correlate_pair(a, b)
        for link in pair_links:
            links.append(link)
            linked_pairs.add(frozenset((a.event_id, b.event_id)))

    # Temporal proximity only added where nothing stronger already
    # links the pair -- avoids flooding the investigator with
    # low-signal links for events that are already related some
    # other, more specific way.
    for a, b in combinations(events, 2):
        pair_key = frozenset((a.event_id, b.event_id))
        if pair_key in linked_pairs:
            continue
        if abs((a.timestamp - b.timestamp)) <= TEMPORAL_PROXIMITY_WINDOW:
            links.append(
                CorrelationLink(
                    event_id_a=a.event_id,
                    event_id_b=b.event_id,
                    rule="temporal_proximity",
                    reason=(
                        f"Events occurred within "
                        f"{TEMPORAL_PROXIMITY_WINDOW.total_seconds():.0f} seconds "
                        f"of each other."
                    ),
                )
            )
            linked_pairs.add(pair_key)

    return links


def _correlate_pair(a: ForensicEvent, b: ForensicEvent) -> List[CorrelationLink]:
    links: List[CorrelationLink] = []

    if a.host and b.host and a.host == b.host:
        links.append(
            CorrelationLink(
                event_id_a=a.event_id,
                event_id_b=b.event_id,
                rule="same_host",
                reason=f"Both events occurred on host '{a.host}'.",
            )
        )

    if a.actor and b.actor and a.actor == b.actor:
        links.append(
            CorrelationLink(
                event_id_a=a.event_id,
                event_id_b=b.event_id,
                rule="same_actor",
                reason=f"Both events involve actor/user '{a.actor}'.",
            )
        )

    if a.process and b.process and a.process == b.process:
        links.append(
            CorrelationLink(
                event_id_a=a.event_id,
                event_id_b=b.event_id,
                rule="same_process",
                reason=f"Both events involve process '{a.process}'.",
            )
        )

    if a.file_path and b.file_path and a.file_path == b.file_path:
        links.append(
            CorrelationLink(
                event_id_a=a.event_id,
                event_id_b=b.event_id,
                rule="same_file",
                reason=f"Both events involve file/object '{a.file_path}'.",
            )
        )

    if a.network and b.network:
        overlap = _network_overlap(a.network, b.network)
        if overlap:
            links.append(
                CorrelationLink(
                    event_id_a=a.event_id,
                    event_id_b=b.event_id,
                    rule="related_network",
                    reason=f"Events share network information: {overlap}.",
                )
            )

    parent_child = _parent_child(a, b)
    if parent_child:
        links.append(parent_child)

    return links


def _network_overlap(net_a: dict, net_b: dict) -> dict:
    """Return the subset of network fields that match between two events."""
    overlap = {}
    for key in ("src_ip", "dst_ip", "dst_port", "domain"):
        if key in net_a and key in net_b and net_a[key] == net_b[key]:
            overlap[key] = net_a[key]
    return overlap


def _parent_child(a: ForensicEvent, b: ForensicEvent):
    """
    Detect a parent-child process relationship, where one event's
    process identifier matches the other event's recorded
    parent_process_id.
    """
    if a.process and b.parent_process_id and a.process == b.parent_process_id:
        return CorrelationLink(
            event_id_a=a.event_id,
            event_id_b=b.event_id,
            rule="parent_child_process",
            reason=f"Process '{b.process}' (event {b.event_id}) has parent "
                   f"process '{a.process}' (event {a.event_id}).",
        )
    if b.process and a.parent_process_id and b.process == a.parent_process_id:
        return CorrelationLink(
            event_id_a=b.event_id,
            event_id_b=a.event_id,
            rule="parent_child_process",
            reason=f"Process '{a.process}' (event {a.event_id}) has parent "
                   f"process '{b.process}' (event {b.event_id}).",
        )
    return None
