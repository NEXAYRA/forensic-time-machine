"""
analyzer.py

Phase-1 AI Engine interface.

IMPORTANT: this module intentionally does NOT call any external AI
service (no Gemini, no OpenAI, no Claude API). It defines the shape
that future AI-assisted analysis will take, backed by a
deterministic, purely rule-based implementation that only ever
describes what is actually present in the evidence.

Ground rules enforced by this module:
- Never claim something happened unless a ForensicEvent or
  CorrelationLink in the timeline actually supports it.
- Every finding must reference the event_id(s) it is based on, so
  an investigator can verify it directly against the evidence.
- Output is explicitly investigative assistance, not a verdict.
  `requires_investigator_review` is always True in Phase 1.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List

from event_schema import Timeline


@dataclass
class Finding:
    """
    A single, evidence-grounded observation about the timeline.

    `statement` must only describe what the referenced events show
    -- never an inferred motive, attribution, or conclusion the
    evidence doesn't directly support.
    """

    statement: str
    supporting_event_ids: List[str]
    rule: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "statement": self.statement,
            "supporting_event_ids": self.supporting_event_ids,
            "rule": self.rule,
        }


@dataclass
class InvestigationSummary:
    """
    The Phase-1 AI Engine's output: a structured, explainable summary
    of a Timeline, always paired with a mandatory investigator-review
    flag.
    """

    event_count: int
    correlation_count: int
    findings: List[Finding] = field(default_factory=list)
    requires_investigator_review: bool = True
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "event_count": self.event_count,
            "correlation_count": self.correlation_count,
            "findings": [f.to_dict() for f in self.findings],
            "requires_investigator_review": self.requires_investigator_review,
            "notes": self.notes,
        }


def analyze_timeline(timeline: Timeline) -> InvestigationSummary:
    """
    Produce a Phase-1 InvestigationSummary from a Timeline.

    This is the interface future LLM integrations should match:
    accept a Timeline, return an InvestigationSummary. Phase 1
    implements it with plain, explainable rules only -- it never
    fabricates a finding that isn't directly backed by an event or
    correlation link already present in the timeline.

    Handles an empty timeline (0 events) without error.
    """
    if not timeline.events:
        return InvestigationSummary(
            event_count=0,
            correlation_count=0,
            findings=[],
            requires_investigator_review=True,
            notes=["No events were provided; nothing to analyze."],
        )

    findings: List[Finding] = []

    # Grounded observation: chronological span of the incident.
    first_event = timeline.events[0]
    last_event = timeline.events[-1]
    findings.append(
        Finding(
            statement=(
                f"Timeline spans from event {first_event.event_id} "
                f"({first_event.event_type} at {first_event.timestamp.isoformat()}) "
                f"to event {last_event.event_id} "
                f"({last_event.event_type} at {last_event.timestamp.isoformat()})."
            ),
            supporting_event_ids=[first_event.event_id, last_event.event_id],
            rule="timeline_span",
        )
    )

    # Grounded observation: summarize correlation links by rule type,
    # without upgrading "correlated" into "caused" or "malicious".
    if timeline.correlations:
        rule_counts: Dict[str, int] = {}
        for link in timeline.correlations:
            rule_counts[link.rule] = rule_counts.get(link.rule, 0) + 1
        for rule, count in rule_counts.items():
            examples = [
                link for link in timeline.correlations if link.rule == rule
            ][:1]
            example_ids = (
                [examples[0].event_id_a, examples[0].event_id_b] if examples else []
            )
            findings.append(
                Finding(
                    statement=(
                        f"{count} event pair(s) are potentially related via "
                        f"the '{rule}' rule. This indicates a possible "
                        f"relationship only -- not confirmed cause or intent."
                    ),
                    supporting_event_ids=example_ids,
                    rule=rule,
                )
            )

    return InvestigationSummary(
        event_count=len(timeline.events),
        correlation_count=len(timeline.correlations),
        findings=findings,
        requires_investigator_review=True,
        notes=[
            "This summary is investigative assistance only.",
            "All findings must be independently verified by a human investigator.",
            "No external AI/LLM service was used to generate this summary (Phase 1).",
        ],
    )
