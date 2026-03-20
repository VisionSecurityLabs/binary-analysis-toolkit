"""
Run the full malware collection and detection enrichment pipeline.

Orchestrates all 5 stages:
  1. Collect samples from MalwareBazaar by tag
  2. Batch-analyze samples with binanalysis
  3. Aggregate results into an enrichment report
  4. Auto-generate detection rules from the report
  5. Validate generated rules against known-clean files

Usage:
    uv run python pipeline/run.py --tags AgentTesla --limit 50
    uv run python pipeline/run.py --tags Emotet Remcos --limit 100 --workers 4 --capa --yara
    uv run python pipeline/run.py --skip-collect --samples samples/  # re-run from analysis
    uv run python pipeline/run.py --tags AgentTesla --dry-run        # preview generated rules
    uv run python pipeline/run.py --tags AgentTesla --clean-dir clean_samples/  # with FP validation
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(
        description="Run the full malware collection and detection enrichment pipeline",
    )

    # Stage 1 — Collect
    parser.add_argument("--tags", nargs="+", default=["AgentTesla"], metavar="TAG",
                        help="Malware tag(s) to query (default: AgentTesla)")
    parser.add_argument("--limit", type=int, default=50,
                        help="Max samples per tag (default: 50)")
    parser.add_argument("--samples", type=Path, default=Path(os.getenv("SAMPLES_DIR", "samples")),
                        help="Samples directory (default: $SAMPLES_DIR or samples/)")

    # Stage 2 — Analyze
    parser.add_argument("--workers", type=int, default=int(os.getenv("BATCH_WORKERS", "2")),
                        help="Parallel analysis workers (default: 2)")
    parser.add_argument("--capa", action="store_true", help="Enable capa analysis")
    parser.add_argument("--yara", action="store_true", help="Enable YARA scanning")

    # Stage 4 — Generate
    parser.add_argument("--min-pct", type=float, default=20.0,
                        help="Minimum corpus prevalence %% for rule generation (default: 20)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview generated rules without writing files")

    # Stage 5 — Validate
    parser.add_argument("--clean-dir", type=Path, default=None,
                        help="Directory of known-clean PEs for false positive validation")
    parser.add_argument("--report-only", action="store_true",
                        help="Report false positives but don't auto-remove rules")

    # Flow control
    parser.add_argument("--skip-collect", action="store_true",
                        help="Skip Stage 1 (use existing samples)")
    parser.add_argument("--skip-analyze", action="store_true",
                        help="Skip Stage 2 (use existing analysis reports)")
    parser.add_argument("--skip-generate", action="store_true",
                        help="Skip Stage 4 (only collect, analyze, aggregate)")

    args = parser.parse_args()
    report_path = Path("enrichment_report.json")

    # ── Stage 1: Collect ──────────────────────────────────────────────────
    if not args.skip_collect:
        print(f"\n{'='*60}")
        print(f"  STAGE 1 — Collect Samples")
        print(f"{'='*60}")
        from pipeline.collect_samples import collect
        collected = collect(args.tags, args.limit, args.samples)
        if not collected and not list(args.samples.glob("*.exe")):
            print("[!] No samples collected and no existing samples found. Aborting.")
            sys.exit(1)
    else:
        print("\n[*] Skipping Stage 1 (--skip-collect)")

    # ── Stage 2: Analyze ──────────────────────────────────────────────────
    if not args.skip_analyze:
        print(f"\n{'='*60}")
        print(f"  STAGE 2 — Batch Analyze")
        print(f"{'='*60}")
        from pipeline.batch_analyze import batch_analyze
        results = batch_analyze(args.samples, args.workers, args.capa, args.yara)
        ok = sum(1 for r in results if r["success"])
        if ok == 0:
            print("[!] No samples analyzed successfully. Aborting.")
            sys.exit(1)
    else:
        print("\n[*] Skipping Stage 2 (--skip-analyze)")

    # ── Stage 3: Aggregate ────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"  STAGE 3 — Aggregate Results")
    print(f"{'='*60}")
    from pipeline.aggregate_results import load_reports, aggregate, print_summary
    import json

    reports = load_reports(args.samples)
    if not reports:
        print(f"[!] No analysis reports found in {args.samples}. Aborting.")
        sys.exit(1)

    enrichment = aggregate(reports)
    print_summary(enrichment)

    with open(report_path, "w") as f:
        json.dump(enrichment, f, indent=2)
    print(f"\n[*] Full report → {report_path}")

    # ── Stage 4: Generate Rules ───────────────────────────────────────────
    if not args.skip_generate:
        print(f"\n{'='*60}")
        print(f"  STAGE 4 — Generate Rules")
        print(f"{'='*60}")
        from pipeline.generate_rules import (
            generate_rules, generate_specimen_rules,
            generate_patterns, generate_ioc_extractors,
            RULES_OUT, SPECIMEN_OUT, PATTERNS_OUT, IOC_OUT,
        )

        outputs: list[tuple[Path, str, str]] = []

        rules_code = generate_rules(enrichment, args.min_pct)
        if rules_code:
            outputs.append((RULES_OUT, rules_code, "behavioral rules"))

        specimen_code = generate_specimen_rules(enrichment)
        if specimen_code:
            outputs.append((SPECIMEN_OUT, specimen_code, "specimen rules"))

        patterns_code = generate_patterns(enrichment)
        if patterns_code:
            outputs.append((PATTERNS_OUT, patterns_code, "string patterns"))

        ioc_code = generate_ioc_extractors(enrichment)
        if ioc_code:
            outputs.append((IOC_OUT, ioc_code, "IOC extractors"))

        if not outputs:
            print("[*] No new rules/patterns to generate — corpus coverage looks good")
        else:
            for path, code, label in outputs:
                if args.dry_run:
                    print(f"\n{'─'*60}")
                    print(f"  {label} → {path}")
                    print(f"{'─'*60}")
                    print(code)
                else:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(code)
                    print(f"  [+] Generated {label} → {path}")

            if not args.dry_run:
                print(f"\n[*] Generated files are auto-loaded by the engine.")
                print(f"    Re-run with --skip-collect --skip-generate to verify improved coverage.")
    else:
        print("\n[*] Skipping Stage 4 (--skip-generate)")

    # ── Stage 5: Validate ────────────────────────────────────────────────
    if args.clean_dir and not args.dry_run and not args.skip_generate:
        print(f"\n{'='*60}")
        print(f"  STAGE 5 — Validate Against Clean Files")
        print(f"{'='*60}")
        from pipeline.validate_rules import validate
        result = validate(args.clean_dir, args.report_only)
        fp_count = len(result.get("false_positives", {}))
        if fp_count and not args.report_only:
            print(f"\n[*] {fp_count} false-positive rules were auto-removed.")
    elif args.clean_dir and args.dry_run:
        print("\n[*] Skipping Stage 5 (--dry-run mode, no rules written to validate)")
    elif not args.clean_dir and not args.skip_generate and not args.dry_run:
        print("\n[*] Tip: use --clean-dir <path> to auto-validate against known-clean PEs")

    print(f"\n{'='*60}")
    print(f"  PIPELINE COMPLETE")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
