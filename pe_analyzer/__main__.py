"""CLI entry point — python -m pe_analyzer <file> [--json]"""

import os
import sys
import json
from pathlib import Path

try:
    import pefile
except ImportError:
    print("[!] pefile not installed. Run: uv add pefile")
    sys.exit(1)

from pe_analyzer.settings import parse_args, build_settings
from pe_analyzer.output import C, heading, subheading, info, warn, danger, detail
from pe_analyzer.strings import extract_ascii_strings, extract_wide_strings
from pe_analyzer.context import build_context
from pe_analyzer.rules import run_behavioral_rules, run_ioc_extractors
from pe_analyzer.integrations.capa_runner import run_capa_analysis
from pe_analyzer.integrations.yara_runner import run_yara_scan
from pe_analyzer.integrations.decompiler import run_decompilation
from pe_analyzer.pe_analysis import (
    analyze_hashes, analyze_pe_headers, analyze_sections, analyze_imports,
    analyze_exports, analyze_resources, analyze_version_info, analyze_tls,
    analyze_imphash, analyze_rich_header, analyze_overlay,
    analyze_strings, analyze_dynamic_apis, analyze_compiler,
)
from pe_analyzer.integrations.dotnet_analyzer import run_dotnet_analysis


def classify(behaviors: list[dict], capa_results: list[dict], yara_results: list[dict]):
    """Print final verdict combining custom rules, capa capabilities, and YARA matches."""
    heading("CLASSIFICATION")

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for b in behaviors:
        counts[b.get("severity", "low")] += 1

    # Boost from capa ATT&CK-mapped offensive capabilities
    offensive_namespaces = {
        "anti-analysis", "collection", "impact", "persistence",
        "exploitation", "communication",
    }
    capa_offensive = [c for c in capa_results
                      if c.get("namespace", "").split("/")[0] in offensive_namespaces
                      or c.get("att&ck")]
    if len(capa_offensive) >= 5:
        counts["high"] += 1
    elif len(capa_offensive) >= 3:
        counts["medium"] += 1

    # Boost from YARA packer / anti-debug hits
    yara_suspicious = [y for y in yara_results
                       if y["source"] in ("antidebug_antivm.yar", "packer.yar")]
    if yara_suspicious:
        counts["medium"] += 1

    # Verdict
    if counts["critical"] > 0:
        danger("VERDICT: MALICIOUS — Critical indicators detected")
    elif counts["high"] >= 2:
        danger("VERDICT: LIKELY MALICIOUS — Multiple high-severity indicators")
    elif counts["high"] >= 1:
        warn("VERDICT: SUSPICIOUS — High-severity indicators present")
    elif counts["medium"] >= 2:
        warn("VERDICT: SUSPICIOUS — Multiple medium-severity indicators")
    else:
        info("VERDICT: No strong malicious indicators (may require dynamic analysis)")

    # Detail breakdown
    if behaviors:
        subheading("Custom Rules")
        for b in behaviors:
            color = C.RED if b["severity"] in ("critical", "high") else C.YELLOW
            print(f"      {color}[{b['severity'].upper()}]{C.RESET} {b['description']}")

    if capa_offensive:
        subheading(f"Capa Offensive Capabilities ({len(capa_offensive)}/{len(capa_results)} total)")
        for c in capa_offensive[:10]:
            att = f"  [{c['att&ck'][0]}]" if c.get("att&ck") else ""
            print(f"      {C.YELLOW}[CAPA]{C.RESET} {c['name']}{att}")

    if yara_suspicious:
        subheading("YARA Suspicious Signatures")
        for y in yara_suspicious:
            print(f"      {C.YELLOW}[YARA]{C.RESET} {y['rule']}  ({y['source']})")


def generate_report(filepath: Path, all_results: dict):
    report_path = filepath.parent / f"{filepath.stem}_analysis.json"
    with open(report_path, "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    heading("REPORT SAVED")
    info(f"JSON report: {report_path}")


def main():
    args = parse_args()

    # Apply GHIDRA_HEADLESS env var before decompiler import uses it
    settings = build_settings(args)
    if settings.ghidra_headless:
        os.environ.setdefault("GHIDRA_HEADLESS", settings.ghidra_headless)

    filepath = args.file

    if not filepath.exists():
        print(f"[!] File not found: {filepath}")
        sys.exit(1)

    with open(filepath, "rb") as f:
        data = f.read()

    if data[:2] != b'MZ':
        print("[!] Not a PE file (missing MZ header)")
        sys.exit(1)

    try:
        pe = pefile.PE(data=data)
    except pefile.PEFormatError as e:
        print(f"[!] Failed to parse PE: {e}")
        sys.exit(1)

    print(f"{C.BOLD}{C.MAGENTA}")
    print("╔══════════════════════════════════════════════════════════════════════╗")
    print("║                    PE BINARY STATIC ANALYZER                       ║")
    print("╚══════════════════════════════════════════════════════════════════════╝")
    print(C.RESET)

    # Pre-extract strings for reuse
    ascii_raw = extract_ascii_strings(data, min_len=4)
    wide_raw = extract_wide_strings(data, min_len=4)
    ascii_set = {s for _, s in ascii_raw}
    wide_set = {s for _, s in wide_raw}

    # Run structural analyses
    results = {}
    results["hashes"] = analyze_hashes(filepath, data)
    results["imphash"] = analyze_imphash(pe)
    results["pe_headers"] = analyze_pe_headers(pe)
    results["rich_header"] = analyze_rich_header(pe)
    results["sections"] = analyze_sections(pe)
    results["imports"] = analyze_imports(pe)
    results["exports"] = analyze_exports(pe)
    results["resources"] = analyze_resources(pe)
    results["version_info"] = analyze_version_info(pe)
    results["tls"] = analyze_tls(pe)
    results["overlay"] = analyze_overlay(data, pe)
    results["compiler"] = analyze_compiler(data, pe, ascii_strs=ascii_set, wide_strs=wide_set)
    results["dotnet"] = run_dotnet_analysis(filepath, pe)
    results["strings"] = analyze_strings(data, ascii_strings=ascii_raw, wide_strings=wide_raw)
    results["dynamic_apis"] = analyze_dynamic_apis(data)

    # Build context for rule engine
    ctx = build_context(
        data=data, pe=pe,
        imports=results["imports"],
        string_findings=results["strings"],
        sections=results["sections"],
        version_info=results["version_info"],
        dynamic_apis=results["dynamic_apis"],
        ascii_strs=ascii_set,
        wide_strs=wide_set,
    )

    # Run behavioral rules and IOC extraction
    behaviors = run_behavioral_rules(ctx)
    results["behavior"] = {"behaviors": behaviors}
    results["iocs"] = run_ioc_extractors(ctx)

    # External tool analysis
    results["capa"] = run_capa_analysis(filepath, rules_path=settings.capa_rules) if settings.run_capa else []
    results["yara"] = run_yara_scan(data, extra_dirs=settings.yara_extra_dirs) if settings.run_yara else []

    # Decompilation (optional) — pass ctx so Ghidra filter adapts to this binary's IOCs
    if settings.run_decompile:
        results["decompilation"] = run_decompilation(filepath, backend=settings.run_decompile, ctx=ctx)

    # Final verdict
    classify(behaviors, results["capa"], results["yara"])

    if settings.save_json:
        results["strings"] = {
            k: [{"value": i["value"], "encoding": i["encoding"]} for i in v]
            for k, v in results["strings"].items()
        }
        generate_report(filepath, results)

    print()


if __name__ == "__main__":
    main()
