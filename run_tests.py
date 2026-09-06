#!/usr/bin/env python3
import importlib
import sys
import traceback
from pathlib import Path

ROOT = Path(__file__).resolve().parent

for module_dir in ("forensic-engine", "timeline-engine", "ai-engine", "tests"):
    path = str(ROOT / module_dir)
    if path not in sys.path:
        sys.path.insert(0, path)

TEST_MODULES = [
    "test_validator",
    "test_normalizer",
    "test_timeline",
    "test_correlation",
    "test_ai",
    "test_integration",
]


def main() -> int:
    total = 0
    passed = 0
    failed = []
    errors = []

    for module_name in TEST_MODULES:
        module = importlib.import_module(module_name)
        test_functions = [
            getattr(module, name)
            for name in dir(module)
            if name.startswith("test_") and callable(getattr(module, name))
        ]
        for fn in test_functions:
            total += 1
            full_name = f"{module_name}.{fn.__name__}"
            try:
                fn()
                passed += 1
                print(f"PASS  {full_name}")
            except AssertionError as e:
                failed.append((full_name, str(e)))
                print(f"FAIL  {full_name}: {e}")
            except Exception as e:
                errors.append((full_name, f"{type(e).__name__}: {e}"))
                print(f"ERROR {full_name}: {type(e).__name__}: {e}")
                traceback.print_exc()

    print("\n" + "=" * 60)
    print(f"Total: {total}  Passed: {passed}  Failed: {len(failed)}  Errors: {len(errors)}")
    print("=" * 60)

    if failed:
        print("\nFailures:")
        for name, msg in failed:
            print(f"  - {name}: {msg}")
    if errors:
        print("\nErrors:")
        for name, msg in errors:
            print(f"  - {name}: {msg}")

    return 0 if not failed and not errors else 1


if __name__ == "__main__":
    sys.exit(main())
