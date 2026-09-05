# NEXAYRA — Phase-1 System Architecture

## Pipeline

Evidence
   ↓
Forensic Processing      (forensic-engine/: validator.py, normalizer.py, evidence.py)
   ↓
Event Normalization      (forensic-engine/normalizer.py -> timeline-engine/event_schema.py)
   ↓
Timeline Reconstruction  (timeline-engine/timeline.py)
   ↓
Event Correlation        (timeline-engine/correlation.py)
   ↓
AI-Assisted Analysis     (ai-engine/analyzer.py)
   ↓
Incident Replay          (Phase 2+, not implemented)
   ↓
Investigator Validation  (human-in-the-loop, always required)

## Module boundaries (contracts)

- forensic-engine owns raw evidence intake, validation, and
  normalization. It depends on the ForensicEvent model defined in
  timeline-engine/event_schema.py but does not depend on
  timeline-engine's ordering/correlation logic.
- timeline-engine owns the common event/timeline data model,
  chronological ordering, and correlation. It does not validate or
  normalize raw evidence.
- ai-engine owns the analysis interface. It consumes a Timeline
  and produces an InvestigationSummary.
- backend wires the above together behind a minimal HTTP API.
- frontend consumes the backend's JSON output.

## Data flow contract

List[dict]              (raw evidence)
  -> validate_events()  -> List[ValidationResult]
  -> normalize_events() -> List[ForensicEvent]
  -> build_timeline()   -> Timeline
  -> analyze_timeline() -> InvestigationSummary

## Import structure

forensic-engine/, timeline-engine/, ai-engine/ are hyphenated
folder names, which Python can't import directly. conftest.py and
backend/main.py add these folders to sys.path so modules import
by plain name (e.g. from event_schema import ForensicEvent).
