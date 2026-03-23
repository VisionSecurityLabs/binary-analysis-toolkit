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
from binanalysis.integrations.vt_lookup import lookup_hash
from binanalysis.generic.path_context import analyze_path_context

# Import format backends to trigger registration
import binanalysis.formats.pe  # noqa: F401

from binanalysis.integrations.capa_runner import run_capa_analysis, update_capa_rules
from binanalysis.integrations.yara_runner import run_yara_scan, download_community_rules
from binanalysis.integrations.decompiler import run_decompilation


def classify(behaviors: list[dict], capa_results: list[dict], yara_results: list[dict],
             legitimacy: dict | None = None):
    """Print final verdict combining custom rules, capa capabilities, YARA matches, and legitimacy signals."""
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

    # --- Legitimacy signals can downgrade the verdict ---
    leg = legitimacy or {}
    legitimacy_hints = []

    if leg.get("is_installer"):
        legitimacy_hints.append(f"Known installer framework: {leg.get('framework', '?')}")
    if leg.get("signed"):
        signer = leg.get("signer", "unknown")
        legitimacy_hints.append(f"Digitally signed by: {signer}")
    if leg.get("known_software"):
        legitimacy_hints.append(f"Known software path: {leg.get('known_software')}")
    if leg.get("vt_clean"):
        legitimacy_hints.append(f"VirusTotal: {leg.get('vt_detection', '0/0')} detections")

    has_strong_legitimacy = len(legitimacy_hints) >= 2

    if counts["critical"] > 0:
        if has_strong_legitimacy:
            warn("VERDICT: SUSPICIOUS — Critical indicators but strong legitimacy signals present")
            info("Review legitimacy signals below — this may be a false positive")
        else:
            danger("VERDICT: MALICIOUS — Critical indicators detected")
    elif counts["high"] >= 2:
        if has_strong_legitimacy:
            warn("VERDICT: SUSPICIOUS — High-severity indicators mitigated by legitimacy signals")
        else:
            danger("VERDICT: LIKELY MALICIOUS — Multiple high-severity indicators")
    elif counts["high"] >= 1:
        if has_strong_legitimacy:
            info("VERDICT: LIKELY BENIGN — Indicators consistent with legitimate software")
        else:
            warn("VERDICT: SUSPICIOUS — High-severity indicators present")
    elif counts["medium"] >= 2:
        if has_strong_legitimacy:
            info("VERDICT: LIKELY BENIGN — Indicators consistent with legitimate software")
        else:
            warn("VERDICT: SUSPICIOUS — Multiple medium-severity indicators")
    else:
        info("VERDICT: No strong malicious indicators (may require dynamic analysis)")

    if legitimacy_hints:
        subheading("Legitimacy Signals")
        for hint in legitimacy_hints:
            print(f"      {C.GREEN}[LEGIT]{C.RESET} {hint}")

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
    print("║            STATIC BINARY ANALYZER — Vision Security Labs             ║")
    print("╚══════════════════════════════════════════════════════════════════════╝")
    print(C.RESET)

    # Pre-extract strings
    ascii_raw = extract_ascii_strings(data, min_len=4)
    wide_raw = extract_wide_strings(data, min_len=4)
    ascii_set = {s for _, s in ascii_raw}
    wide_set = {s for _, s in wide_raw}

    # Path context analysis (before format-specific)
    path_context = analyze_path_context(args.file)  # use original path, not unpacked

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

    if settings.run_decompile:
        decompile_results = run_decompilation(filepath, backend=settings.run_decompile, ctx=ctx)
    else:
        decompile_results = {}

    # VirusTotal lookup
    if settings.run_vt:
        vt_results = lookup_hash(generic_results["hashes"]["sha256"])
    else:
        vt_results = {}

    # Build legitimacy signals for verdict
    fmt_results = generic_results.get("format_specific", {})
    legitimacy = {}
    installer_info = fmt_results.get("installer", {})
    if installer_info.get("is_installer"):
        legitimacy["is_installer"] = True
        legitimacy["framework"] = installer_info.get("framework", "")
    sig_info = fmt_results.get("signature", {})
    if sig_info.get("signed"):
        legitimacy["signed"] = True
        legitimacy["signer"] = sig_info.get("signer", "unknown")
    if path_context.get("known_software"):
        legitimacy["known_software"] = path_context["known_software"]
    if vt_results.get("found") and vt_results.get("malicious", 999) == 0:
        legitimacy["vt_clean"] = True
        legitimacy["vt_detection"] = vt_results.get("detection_ratio", "0/0")

    # Verdict
    classify(behaviors, capa_results, yara_results, legitimacy=legitimacy)

    results = {
        "generic": {
            "hashes": generic_results["hashes"],
            "strings": {
                k: [{"value": i["value"], "encoding": i["encoding"]} for i in v]
                for k, v in generic_results["strings"].items()
            },
            "dynamic_apis": generic_results["dynamic_apis"],
            "path_context": path_context,
        },
        "format_specific": fmt_results,
        "behavior": {"behaviors": behaviors},
        "iocs": iocs,
        "capa": capa_results,
        "yara": yara_results,
        "decompile": decompile_results,
        "virustotal": vt_results,
        "legitimacy": legitimacy,
    }
    generate_report(filepath, results)
    html_path = save_html_report(results, filepath)
    info(f"HTML report: {html_path}")
    if settings.debug or settings.run_report:
        generate_llm_report(results, filepath,
                            llm_url=settings.llm_url,
                            llm_model=settings.llm_model,
                            timeout=settings.llm_timeout,
                            debug=settings.debug,
                            dry_run=not settings.run_report)

    print()


if __name__ == "__main__":
    main()
