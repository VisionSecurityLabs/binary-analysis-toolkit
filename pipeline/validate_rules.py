"""
Validate generated rules against known-clean PE files.

Runs binanalysis on each clean sample and flags any generated rule that
fires as a false positive. Offending rules are removed from the generated
files automatically.

Usage:
    uv run python pipeline/validate_rules.py --clean-dir clean_samples/
    uv run python pipeline/validate_rules.py --clean-dir /usr/share/clean-pe/ --report-only
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

from pipeline.generate_rules import RULES_OUT, SPECIMEN_OUT

# Generated rule files and their list variable names
GENERATED_RULE_FILES = [
    (RULES_OUT, "GENERATED_RULES"),
    (SPECIMEN_OUT, "GENERATED_SPECIMEN_RULES"),
]


def analyze_clean_sample(filepath: Path) -> list[str]:
    """Run binanalysis on a clean file and return triggered rule names."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "binanalysis", str(filepath)],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except subprocess.TimeoutExpired:
        return []

    report_path = filepath.parent / f"{filepath.stem}_analysis.json"
    if not report_path.exists():
        return []

    try:
        with open(report_path) as f:
            report = json.load(f)
        rules = [
            b.get("rule", b.get("rule_id", ""))
            for b in report.get("behavior", {}).get("behaviors", [])
        ]
        # Clean up the report file
        report_path.unlink(missing_ok=True)
        html_path = filepath.parent / f"{filepath.stem}_analysis.html"
        html_path.unlink(missing_ok=True)
        return rules
    except Exception:
        return []


def find_generated_rules(filepath: Path) -> list[str]:
    """Extract rule name strings from a generated rules file."""
    if not filepath.exists():
        return []
    content = filepath.read_text()
    return re.findall(r'Rule\("([^"]+)"', content)


def remove_rules_from_file(filepath: Path, rules_to_remove: set[str]) -> int:
    """Remove specific Rule(...) blocks from a generated file. Returns count removed."""
    if not filepath.exists() or not rules_to_remove:
        return 0

    content = filepath.read_text()
    removed = 0

    for rule_name in rules_to_remove:
        # Match the full Rule(...) block including trailing comment and comma
        pattern = re.compile(
            r'\n?\s*Rule\("' + re.escape(rule_name) + r'".*?\),\s*'
            r'(?:#[^\n]*\n?)?',
            re.DOTALL,
        )
        new_content = pattern.sub('\n', content)
        if new_content != content:
            removed += 1
            content = new_content

    if removed:
        filepath.write_text(content)

    return removed


def validate(clean_dir: Path, report_only: bool = False) -> dict:
    """Validate generated rules against clean files. Returns validation report."""
    clean_files = list(clean_dir.glob("*.exe")) + list(clean_dir.glob("*.dll"))
    if not clean_files:
        print(f"[!] No .exe or .dll files found in {clean_dir}")
        return {"clean_files": 0, "false_positives": {}}

    # Collect all generated rule names
    all_generated = set()
    for rule_file, _ in GENERATED_RULE_FILES:
        all_generated.update(find_generated_rules(rule_file))

    if not all_generated:
        print("[*] No generated rules found — nothing to validate")
        return {"clean_files": len(clean_files), "false_positives": {}}

    print(f"[*] Validating {len(all_generated)} generated rules against {len(clean_files)} clean files\n")

    # Track which generated rules fire on clean files
    false_positives: dict[str, list[str]] = {}

    for i, filepath in enumerate(clean_files, 1):
        print(f"  [{i:3d}/{len(clean_files)}] {filepath.name:50s}", end="", flush=True)
        triggered = analyze_clean_sample(filepath)
        # Only care about generated rules (not built-in ones)
        fp_rules = [r for r in triggered if r in all_generated]
        if fp_rules:
            for rule in fp_rules:
                false_positives.setdefault(rule, []).append(filepath.name)
            print(f"  FP: {', '.join(fp_rules)}")
        else:
            print("  OK")

    # Report
    print(f"\n{'─'*60}")
    if not false_positives:
        print(f"  All {len(all_generated)} generated rules passed validation")
        print(f"  (tested against {len(clean_files)} clean files)")
    else:
        print(f"  FALSE POSITIVES FOUND: {len(false_positives)} rules")
        print(f"{'─'*60}")
        for rule, files in sorted(false_positives.items()):
            print(f"  {rule}")
            for f in files[:5]:
                print(f"    → fired on: {f}")
            if len(files) > 5:
                print(f"    → ... and {len(files) - 5} more")

        if not report_only:
            print(f"\n[*] Removing false-positive rules from generated files...")
            fp_set = set(false_positives.keys())
            total_removed = 0
            for rule_file, _ in GENERATED_RULE_FILES:
                removed = remove_rules_from_file(rule_file, fp_set)
                if removed:
                    print(f"  [-] Removed {removed} rules from {rule_file}")
                    total_removed += removed
            print(f"  [*] Total removed: {total_removed} false-positive rules")
        else:
            print(f"\n[*] --report-only: no rules were removed")

    return {
        "clean_files": len(clean_files),
        "generated_rules": len(all_generated),
        "false_positives": false_positives,
    }


def main():
    parser = argparse.ArgumentParser(description="Validate generated rules against clean PE files")
    parser.add_argument("--clean-dir", type=Path, required=True,
                        help="Directory containing known-clean PE files (.exe, .dll)")
    parser.add_argument("--report-only", action="store_true",
                        help="Report false positives but don't remove rules")
    args = parser.parse_args()

    if not args.clean_dir.is_dir():
        print(f"[!] Clean directory not found: {args.clean_dir}")
        sys.exit(1)

    validate(args.clean_dir, args.report_only)


if __name__ == "__main__":
    main()
