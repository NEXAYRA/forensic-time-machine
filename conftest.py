import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

for module_dir in ("forensic-engine", "timeline-engine", "ai-engine"):
    path = str(ROOT / module_dir)
    if path not in sys.path:
        sys.path.insert(0, path)
