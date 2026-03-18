"""CLI entry point — python -m binanalysis <file>"""

import sys
import json
from pathlib import Path

from binanalysis.output import C, heading, subheading, info, warn, danger, detail
from binanalysis.strings import extract_ascii_strings, extract_wide_strings
from binanalysis.generic.hashes import analyze_hashes
from binanalysis.generic.strings import analyze_strings, analyze_dynamic_apis
from binanalysis.rules import run_behavioral_rules, run_ioc_extractors
from binanalysis.formats import detect_format
from binanalysis.settings import parse_args, build_settings
from binanalysis.integrations.unpacker import try_unpack_upx
from binanalysis.integrations.llm_report import generate_llm_report
from binanalysis.integrations.html_report import save_html_report

# Import format backends to trigger registration
import binanalysis.formats.pe  # noqa: F401

from binanalysis.integrations.capa_runner import run_capa_analysis, update_capa_rules
from binanalysis.integrations.yara_runner import run_yara_scan, download_community_rules


def classify(behaviors: list[dict], capa_results: list[dict], yara_results: list[dict]):
    """Print final verdict combining custom rules, capa capabilities, and YARA matches."""
    heading("CLASSIFICATION")

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for b in behaviors:
        counts[b.get("severity", "low")] += 1

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

    yara_suspicious = [y for y in yara_results
                       if y["source"] in ("antidebug_antivm.yar", "packer.yar")]
    if yara_suspicious:
        counts["medium"] += 1

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
    settings = build_settings(args)

    if getattr(args, "update_capa", False):
        update_capa_rules(rules_path=settings.capa_rules, repos=settings.capa_repos)

    if getattr(args, "update_yara", False):
        download_community_rules(community_dir=settings.yara_community_dir,
                                 repos=settings.yara_repos)

    filepath = args.file

    if not filepath.exists():
        print(f"[!] File not found: {filepath}")
        sys.exit(1)

    with open(filepath, "rb") as f:
        data = f.read()

    # UPX unpack attempt
    unpacked = try_unpack_upx(filepath)
    if unpacked:
        filepath = unpacked
        data = open(filepath, "rb").read()

    handler = detect_format(data)
    if handler is None:
        print("[!] Unsupported binary format (not PE, ELF, or Mach-O)")
        sys.exit(1)

    print(f"{C.BOLD}{C.MAGENTA}")
    print("╔══════════════════════════════════════════════════════════════════════╗")
    print("║                   STATIC BINARY ANALYZER                           ║")
    print("║                                          Vision Security Labs       ║")
    print("╚══════════════════════════════════════════════════════════════════════╝")
    print(C.RESET)

    # Pre-extract strings
    ascii_raw = extract_ascii_strings(data, min_len=4)
    wide_raw = extract_wide_strings(data, min_len=4)
    ascii_set = {s for _, s in ascii_raw}
    wide_set = {s for _, s in wide_raw}

    # Generic analysis
    generic_results = {
        "ascii_set": ascii_set,
        "wide_set": wide_set,
    }
    generic_results["hashes"] = analyze_hashes(filepath, data)
    generic_results["strings"] = analyze_strings(data, ascii_strings=ascii_raw, wide_strings=wide_raw)
    generic_results["dynamic_apis"] = analyze_dynamic_apis(data)

    # Format-specific analysis
    ctx = handler.analyze(filepath, data, generic_results)

    info(f"Format: {handler.name}")
    if hasattr(ctx, 'pe'):
        machine = generic_results.get("format_specific", {}).get("pe_headers", {}).get("machine", "?")
        subsys = generic_results.get("format_specific", {}).get("pe_headers", {}).get("subsystem", "?")
        detail("Architecture", f"{machine}, {subsys}")

    # Behavioral rules: generic + format-specific
    format_rules = handler.get_rules()
    behaviors = run_behavioral_rules(ctx, format_rules=format_rules)

    # IOC extraction
    iocs = run_ioc_extractors(ctx)

    # Integrations
    if settings.run_capa:
        capa_results = run_capa_analysis(filepath, rules_path=settings.capa_rules,
                                         repos=settings.capa_repos)
    else:
        capa_results = []

    if settings.run_yara:
        yara_results = run_yara_scan(data, extra_dirs=settings.yara_extra_dirs or None,
                                     community_dir=settings.yara_community_dir,
                                     repos=settings.yara_repos)
    else:
        yara_results = []

    # Verdict
    classify(behaviors, capa_results, yara_results)

    results = {
        "generic": {
            "hashes": generic_results["hashes"],
            "strings": {
                k: [{"value": i["value"], "encoding": i["encoding"]} for i in v]
                for k, v in generic_results["strings"].items()
            },
            "dynamic_apis": generic_results["dynamic_apis"],
        },
        "format_specific": generic_results.get("format_specific", {}),
        "behavior": {"behaviors": behaviors},
        "iocs": iocs,
        "capa": capa_results,
        "yara": yara_results,
    }
    generate_report(filepath, results)
    html_path = save_html_report(results, filepath)
    info(f"HTML report: {html_path}")
    if settings.run_report:
        generate_llm_report(results, filepath,
                            llm_url=settings.llm_url,
                            llm_model=settings.llm_model,
                            timeout=settings.llm_timeout,
                            debug=settings.debug)

    print()


if __name__ == "__main__":
    main()
