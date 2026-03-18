"""CLI entry point — python -m bat_analyzer <file> [--json]"""

import os
import sys
import json
import logging
from pathlib import Path

try:
    import pefile
except ImportError:
    print("[!] pefile not installed. Run: uv add pefile")
    sys.exit(1)

from bat_analyzer.settings import parse_args, build_settings, Settings
from bat_analyzer.output import C, heading, subheading, info, warn, danger, detail
from bat_analyzer.strings import extract_ascii_strings, extract_wide_strings
from bat_analyzer.context import build_context, AnalysisContext
from bat_analyzer.rules import run_behavioral_rules, run_ioc_extractors
from bat_analyzer.integrations.capa_runner import run_capa_analysis
from bat_analyzer.integrations.yara_runner import run_yara_scan
from bat_analyzer.integrations.decompiler import run_decompilation
from bat_analyzer.integrations.llm_report import generate_llm_report
from bat_analyzer.integrations.unpacker import try_unpack_upx
from bat_analyzer.pe_analysis import (
    analyze_hashes, analyze_pe_headers, analyze_sections, analyze_imports,
    analyze_exports, analyze_resources, analyze_version_info, analyze_tls,
    analyze_imphash, analyze_rich_header, analyze_overlay,
    analyze_strings, analyze_dynamic_apis, analyze_compiler,
)
from bat_analyzer.integrations.dotnet_analyzer import run_dotnet_analysis

logger = logging.getLogger(__name__)


def classify(behaviors: list[dict], capa_results: list[dict], yara_results: list[dict],
             string_findings: dict | None = None):
    """Print final verdict using weighted scoring across all evidence layers."""
    heading("CLASSIFICATION")

    # ── Weighted scoring ──
    SEVERITY_WEIGHTS = {"critical": 10, "high": 5, "medium": 2, "low": 1}
    score = 0

    # Behavioral rules
    for b in behaviors:
        score += SEVERITY_WEIGHTS.get(b.get("severity", "low"), 1)

    # String finding weights
    if string_findings:
        for cat, items in string_findings.items():
            if items:
                best_weight = max(item.get("weight", 1) for item in items)
                score += best_weight

    # Capa offensive capabilities
    offensive_namespaces = {
        "anti-analysis", "collection", "impact", "persistence",
        "exploitation", "communication",
    }
    capa_offensive = [c for c in capa_results
                      if c.get("namespace", "").split("/")[0] in offensive_namespaces
                      or c.get("att&ck")]
    score += len(capa_offensive) * 3

    # YARA matches
    yara_suspicious = [y for y in yara_results
                       if y["source"] in ("antidebug_antivm.yar", "packer.yar")]
    score += len(yara_suspicious) * 4

    # ── Verdict thresholds ──
    if score >= 50:
        danger(f"VERDICT: MALICIOUS — Threat score {score}/100+")
    elif score >= 30:
        danger(f"VERDICT: LIKELY MALICIOUS — Threat score {score}")
    elif score >= 15:
        warn(f"VERDICT: SUSPICIOUS — Threat score {score}")
    elif score >= 5:
        warn(f"VERDICT: LOW CONFIDENCE — Threat score {score}")
    else:
        info(f"VERDICT: No strong malicious indicators — Threat score {score}")

    # ── Detail breakdown ──
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


def _parse_and_load(args) -> tuple[Path, bytes, pefile.PE, Settings]:
    """Parse CLI, load file, validate PE, try UPX unpack."""
    settings = build_settings(args)
    if settings.ghidra_headless:
        os.environ.setdefault("GHIDRA_HEADLESS", settings.ghidra_headless)

    filepath = args.file

    if not filepath.exists():
        print(f"[!] File not found: {filepath}")
        sys.exit(1)

    with open(filepath, "rb") as f:
        data = f.read()

    logger.debug("Loaded %s (%d bytes)", filepath, len(data))

    if data[:2] != b'MZ':
        print("[!] Not a PE file (missing MZ header)")
        sys.exit(1)

    try:
        pe = pefile.PE(data=data)
    except pefile.PEFormatError as e:
        print(f"[!] Failed to parse PE: {e}")
        sys.exit(1)

    # Try UPX unpacking — if successful, re-read and re-parse
    unpacked_path = try_unpack_upx(filepath)
    logger.debug("UPX unpack: %s", unpacked_path)
    if unpacked_path:
        with open(unpacked_path, "rb") as f:
            data = f.read()
        pe = pefile.PE(data=data)

    return filepath, data, pe, settings


def _run_structural_analysis(filepath, data, pe, ascii_raw, wide_raw) -> dict:
    """Run all PE structural analysis stages. Returns results dict."""
    ascii_set = {s for _, s in ascii_raw}
    wide_set = {s for _, s in wide_raw}

    logger.debug("Running %s...", "structural analysis")

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

    logger.debug("Found %d string categories", len(results["strings"]))

    return results


def _run_behavioral_analysis(data, pe, results, ascii_set, wide_set) -> tuple[list, AnalysisContext]:
    """Build context, run behavioral rules and IOC extraction."""
    logger.debug("Running %s...", "behavioral analysis")

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

    behaviors = run_behavioral_rules(ctx)
    results["behavior"] = {"behaviors": behaviors}
    results["iocs"] = run_ioc_extractors(ctx)

    logger.debug("%d behavioral rules triggered", len(behaviors))

    return behaviors, ctx


def _run_integrations(filepath, data, settings, args, ctx, results) -> None:
    """Run optional integrations: capa, YARA, decompiler, LLM report."""
    logger.debug("Running %s...", "integrations")

    # Capa
    results["capa"] = run_capa_analysis(filepath, rules_path=settings.capa_rules) if settings.run_capa else []

    # YARA
    if settings.run_yara:
        if getattr(args, "update_yara", False):
            from bat_analyzer.integrations.yara_runner import download_community_rules
            download_community_rules()
        results["yara"] = run_yara_scan(data, extra_dirs=settings.yara_extra_dirs)
    else:
        results["yara"] = []

    # Decompilation (optional) — pass ctx so Ghidra filter adapts to this binary's IOCs
    if settings.run_decompile:
        results["decompilation"] = run_decompilation(filepath, backend=settings.run_decompile, ctx=ctx)

    # LLM-powered analyst report (optional)
    if settings.run_report:
        report_text = generate_llm_report(
            results, filepath,
            llm_url=settings.llm_url,
            llm_model=settings.llm_model,
            timeout=settings.llm_timeout,
            debug=settings.debug,
        )
        if report_text:
            results["llm_report"] = report_text


def main():
    args = parse_args()
    filepath, data, pe, settings = _parse_and_load(args)

    logging.basicConfig(
        level=logging.DEBUG if settings.debug else logging.WARNING,
        format="%(name)s %(levelname)s: %(message)s",
    )

    # Banner
    print(f"{C.BOLD}{C.MAGENTA}")
    print("╔══════════════════════════════════════════════════════════════════════╗")
    print("║                   BINARY ANALYSIS TOOLKIT (BAT)                    ║")
    print("╚══════════════════════════════════════════════════════════════════════╝")
    print(C.RESET)

    # Pre-extract strings for reuse
    ascii_raw = extract_ascii_strings(data, min_len=4)
    wide_raw = extract_wide_strings(data, min_len=4)
    ascii_set = {s for _, s in ascii_raw}
    wide_set = {s for _, s in wide_raw}

    results = _run_structural_analysis(filepath, data, pe, ascii_raw, wide_raw)
    behaviors, ctx = _run_behavioral_analysis(data, pe, results, ascii_set, wide_set)
    _run_integrations(filepath, data, settings, args, ctx, results)

    # Final verdict
    classify(behaviors, results["capa"], results["yara"], results["strings"])

    if settings.save_json:
        results["strings"] = {
            k: [{"value": i["value"], "encoding": i["encoding"]} for i in v]
            for k, v in results["strings"].items()
        }
        generate_report(filepath, results)

    print()


if __name__ == "__main__":
    main()
