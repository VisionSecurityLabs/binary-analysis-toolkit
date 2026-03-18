"""
Run binanalysis on a directory of PE samples in parallel.

Usage:
    python pipeline/batch_analyze.py
    python pipeline/batch_analyze.py --samples samples/ --workers 4 --capa --yara

Results: each sample gets a <name>_analysis.json and <name>_analysis.html
written next to it in the samples directory.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

TIMEOUT_SECONDS = 300  # 5 min per sample (capa can be slow)


def analyze_one(args: tuple[Path, bool, bool]) -> dict:
    """Worker: run binanalysis on a single file. Returns a result record."""
    filepath, run_capa, run_yara = args
    cmd = [sys.executable, "-m", "binanalysis", str(filepath)]
    if run_capa:
        cmd.append("--capa")
    if run_yara:
        cmd.append("--yara")

    start = time.monotonic()
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=TIMEOUT_SECONDS,
        )
        elapsed = time.monotonic() - start
        report_path = filepath.parent / f"{filepath.stem}_analysis.json"
        success = result.returncode == 0 and report_path.exists()
        return {
            "file": str(filepath.name),
            "sha256": filepath.stem,
            "success": success,
            "elapsed": round(elapsed, 1),
            "report": str(report_path) if success else None,
            "error": result.stderr.strip()[-300:] if not success else None,
        }
    except subprocess.TimeoutExpired:
        return {
            "file": str(filepath.name),
            "sha256": filepath.stem,
            "success": False,
            "elapsed": TIMEOUT_SECONDS,
            "report": None,
            "error": "TIMEOUT",
        }
    except Exception as e:
        return {
            "file": str(filepath.name),
            "sha256": filepath.stem,
            "success": False,
            "elapsed": 0,
            "report": None,
            "error": str(e),
        }


def batch_analyze(samples_dir: Path, workers: int, run_capa: bool, run_yara: bool) -> list[dict]:
    pe_files = [
        f for f in samples_dir.glob("*.exe")
        if not f.name.endswith("_analysis.json")
    ]
    if not pe_files:
        print(f"[!] No .exe files found in {samples_dir}")
        return []

    print(f"[*] Analyzing {len(pe_files)} samples with {workers} workers")
    print(f"    Options: capa={run_capa}  yara={run_yara}  timeout={TIMEOUT_SECONDS}s\n")

    job_args = [(f, run_capa, run_yara) for f in pe_files]
    results = []
    done = 0

    with ProcessPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(analyze_one, a): a[0] for a in job_args}
        for future in as_completed(futures):
            rec = future.result()
            done += 1
            status = "OK " if rec["success"] else "ERR"
            err_hint = f"  [{rec['error'][:60]}]" if rec.get("error") else ""
            print(f"  [{done:3d}/{len(pe_files)}] [{status}] {rec['file']:50s} {rec['elapsed']:6.1f}s{err_hint}")
            results.append(rec)

    ok = sum(1 for r in results if r["success"])
    print(f"\n[*] Done — {ok}/{len(results)} succeeded")

    summary_path = samples_dir / "batch_summary.json"
    with open(summary_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"[*] Batch summary → {summary_path}")

    return results


def main():
    parser = argparse.ArgumentParser(description="Batch-run binanalysis on PE samples")
    parser.add_argument("--samples", type=Path, default=Path(os.getenv("SAMPLES_DIR", "samples")),
                        help="Directory containing PE files (default: $SAMPLES_DIR or samples/)")
    parser.add_argument("--workers", type=int, default=int(os.getenv("BATCH_WORKERS", "2")),
                        help="Parallel workers (default: 2; capa is CPU-heavy)")
    parser.add_argument("--capa", action="store_true", help="Enable capa analysis")
    parser.add_argument("--yara", action="store_true", help="Enable YARA scanning")
    args = parser.parse_args()

    batch_analyze(args.samples, args.workers, args.capa, args.yara)


if __name__ == "__main__":
    main()
