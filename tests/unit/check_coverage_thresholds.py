"""Validate per-scope coverage thresholds from coverage.xml.

Usage:
  python tests/unit/check_coverage_thresholds.py [coverage.xml]
"""

from __future__ import annotations

import sys
import xml.etree.ElementTree as ET
from pathlib import Path


MODULES_MIN = 85.0
MODULE_UTILS_MIN = 90.0


def _scope_coverage(report_path: Path) -> tuple[float, float]:
    if not report_path.exists():
        raise FileNotFoundError(f"coverage report not found: {report_path}")

    root = ET.parse(report_path).getroot()

    module_files = {p.name for p in Path("plugins/modules").glob("*.py")}
    util_files = {p.name for p in Path("plugins/module_utils").glob("*.py")}

    mod_cov = mod_total = 0
    util_cov = util_total = 0

    for cls in root.findall(".//class"):
        name = Path(cls.attrib.get("filename", "")).name
        lines = cls.findall("./lines/line")
        total = len(lines)
        covered = sum(1 for line in lines if int(line.attrib.get("hits", "0")) > 0)

        if name in module_files:
            mod_total += total
            mod_cov += covered
        elif name in util_files:
            util_total += total
            util_cov += covered

    modules_pct = (mod_cov / mod_total * 100.0) if mod_total else 0.0
    utils_pct = (util_cov / util_total * 100.0) if util_total else 0.0
    return modules_pct, utils_pct


def main() -> int:
    report = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("coverage.xml")
    modules_pct, utils_pct = _scope_coverage(report)

    print(f"modules coverage: {modules_pct:.2f}% (required >= {MODULES_MIN:.2f}%)")
    print(
        f"module_utils coverage: {utils_pct:.2f}% (required >= {MODULE_UTILS_MIN:.2f}%)"
    )

    failures = []
    if modules_pct < MODULES_MIN:
        failures.append("modules")
    if utils_pct < MODULE_UTILS_MIN:
        failures.append("module_utils")

    if failures:
        print(
            "Coverage thresholds not met for: " + ", ".join(failures),
            file=sys.stderr,
        )
        return 1

    print("Coverage thresholds satisfied.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
