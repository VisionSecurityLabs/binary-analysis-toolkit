"""
Auto-generate detection improvements from an enrichment report.

Reads enrichment_report.json (output of aggregate_results.py) and generates:
  1. New behavioral rules   → binanalysis/formats/pe/rules/generated.py
  2. New string patterns     → binanalysis/generated_patterns.py
  3. New IOC extractors      → binanalysis/generated_ioc.py

Generated files are importable modules that plug into the existing engine.
Review before committing — not all suggestions will be good rules.

Usage:
    uv run python pipeline/generate_rules.py
    uv run python pipeline/generate_rules.py --report enrichment_report.json --dry-run
"""

from __future__ import annotations

import argparse
import json
import re
import textwrap
from pathlib import Path

REPORT_DEFAULT = Path("enrichment_report.json")

RULES_OUT = Path("binanalysis/formats/pe/rules/generated.py")
SPECIMEN_OUT = Path("binanalysis/formats/pe/rules/generated_specimen.py")
PATTERNS_OUT = Path("binanalysis/generated_patterns.py")
IOC_OUT = Path("binanalysis/generated_ioc.py")

# Categories inferred from API names
API_CATEGORY_MAP = {
    "Virtual": "injection", "NtMap": "injection", "NtWrite": "injection",
    "NtAllocate": "injection", "WriteProcess": "injection", "ReadProcess": "injection",
    "CreateRemote": "injection", "QueueUser": "injection", "SetThread": "injection",
    "CreateProcess": "execution", "WinExec": "execution", "ShellExecute": "execution",
    "Crypt": "crypto", "BCrypt": "crypto",
    "WSA": "network", "connect": "network", "send": "network", "recv": "network",
    "Internet": "network", "HttpSend": "network", "WinHttp": "network",
    "URLDownload": "network",
    "RegOpen": "persistence", "RegSet": "persistence", "RegCreate": "persistence",
    "OpenProcess": "privilege_escalation", "AdjustToken": "privilege_escalation",
    "LookupPrivilege": "privilege_escalation",
    "GetProcAddress": "execution", "LoadLibrary": "execution",
}

SEVERITY_BY_CATEGORY = {
    "injection": "high",
    "execution": "medium",
    "crypto": "low",
    "network": "medium",
    "persistence": "high",
    "privilege_escalation": "high",
}


def _slugify(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_")


def _infer_category(api_name: str) -> str:
    for prefix, cat in API_CATEGORY_MAP.items():
        if api_name.startswith(prefix):
            return cat
    return "suspicious_api"


def _infer_pair_category(a: str, b: str) -> str:
    cat_a = _infer_category(a)
    cat_b = _infer_category(b)
    if cat_a == cat_b:
        return cat_a
    # Mixed categories — pick the more severe one
    order = ["injection", "privilege_escalation", "persistence", "network", "execution", "crypto", "suspicious_api"]
    for cat in order:
        if cat in (cat_a, cat_b):
            return cat
    return "suspicious_api"


def generate_rules(report: dict, min_pct: float) -> str:
    """Generate behavioral rules from uncovered APIs and pairs."""
    cands = report.get("enrichment_candidates", {})
    single_apis = cands.get("uncovered_single_apis", [])
    api_pairs = cands.get("uncovered_api_pairs", [])

    rules: list[str] = []

    for entry in single_apis:
        api = entry["api"]
        pct = entry["pct"]
        if pct < min_pct:
            continue
        cat = _infer_category(api)
        sev = SEVERITY_BY_CATEGORY.get(cat, "medium")
        slug = _slugify(f"gen_{api}")
        rules.append(
            f'    Rule("{slug}", "{cat}", "{sev}",\n'
            f'         "Auto-generated: {api} detected in {{pct}}% of corpus",\n'
            f'         lambda ctx: ctx.has_import("{api}")),'.replace("{pct}", str(pct))
        )

    for entry in api_pairs:
        a, b = entry["pair"]
        pct = entry["pct"]
        if pct < min_pct:
            continue
        cat = _infer_pair_category(a, b)
        sev = SEVERITY_BY_CATEGORY.get(cat, "medium")
        slug = _slugify(f"gen_{a}_{b}")
        rules.append(
            f'    Rule("{slug}", "{cat}", "{sev}",\n'
            f'         "Auto-generated: {a} + {b} ({{pct}}% of corpus)",\n'
            f'         lambda ctx: ctx.has_all_imports("{a}", "{b}")),'.replace("{pct}", str(pct))
        )

    if not rules:
        return ""

    rules_block = "\n\n".join(rules)
    return textwrap.dedent(f'''\
        """Auto-generated behavioral rules from enrichment pipeline.

        Review these rules before committing. Generated from corpus analysis
        of {{total}} samples.
        """

        from binanalysis.rules import Rule

        GENERATED_RULES: list[Rule] = [
        {{rules_block}}
        ]
    ''').replace("{total}", str(report["meta"]["total_samples"])).replace("{rules_block}", rules_block)


def generate_patterns(report: dict) -> str:
    """Generate string patterns from recurring URLs and registry keys."""
    cands = report.get("enrichment_candidates", {})
    urls = cands.get("recurring_urls", [])
    registry = cands.get("recurring_registry_keys", [])

    patterns: list[str] = []

    for entry in urls:
        raw = entry["pattern"]
        # Escape for regex and truncate to domain+path prefix
        escaped = re.escape(raw).replace(r"\ ", r"\s")
        # Extract domain portion for a tighter pattern
        m = re.match(r"https?://([^/]+)", raw)
        if m:
            domain = re.escape(m.group(1))
            patterns.append(
                f'    StringPattern(r"{domain}", "gen_c2_domain", 6),'
            )

    for entry in registry:
        raw = entry["pattern"]
        escaped = re.escape(raw)
        patterns.append(
            f'    StringPattern(r"{escaped}", "gen_registry_key", 4),'
        )

    if not patterns:
        return ""

    # Deduplicate
    seen = set()
    unique: list[str] = []
    for p in patterns:
        if p not in seen:
            seen.add(p)
            unique.append(p)

    patterns_block = "\n".join(unique)
    return textwrap.dedent(f'''\
        """Auto-generated string patterns from enrichment pipeline.

        Review before committing. Merge useful patterns into config.py.
        """

        from binanalysis.config import StringPattern

        GENERATED_PATTERNS = [
        {{patterns_block}}
        ]
    ''').replace("{patterns_block}", patterns_block)


def generate_specimen_rules(report: dict) -> str:
    """Generate family-specific specimen rules from per-family profiles."""
    profiles = report.get("family_profiles", {})
    if not profiles:
        return ""

    rules: list[str] = []

    for family, profile in profiles.items():
        slug = _slugify(family)
        apis = profile.get("distinctive_apis", [])
        strings = profile.get("distinctive_strings", [])
        count = profile.get("sample_count", 0)

        # Generate import-based specimen rule if family has distinctive APIs
        if len(apis) >= 2:
            # Pick top 3 most distinctive APIs for a combo check
            check_apis = apis[:3]
            api_checks = " and ".join(f'ctx.has_import("{a}")' for a in check_apis)
            apis_desc = " + ".join(check_apis)
            rules.append(
                f'    Rule("specimen_{slug}_apis", "family_detection", "high",\n'
                f'         "{family} family: distinctive API combo ({apis_desc})",\n'
                f'         lambda ctx, _a={check_apis!r}: all(ctx.has_import(a) for a in _a)),\n'
                f'    # Based on {count} samples'
            )

        # Generate string-based specimen rule if family has distinctive strings
        if strings:
            # Pick strings that look most like identifiers (not generic paths)
            best = [s for s in strings if len(s) >= 10][:3]
            if best:
                strings_repr = repr(best)
                rules.append(
                    f'    Rule("specimen_{slug}_strings", "family_detection", "high",\n'
                    f'         "{family} family: distinctive string patterns",\n'
                    f'         lambda ctx, _s={strings_repr}: any(ctx.has_string_containing(s) for s in _s)),\n'
                    f'    # Based on {count} samples'
                )

    if not rules:
        return ""

    rules_block = "\n\n".join(rules)
    total = report["meta"]["total_samples"]
    families_list = ", ".join(profiles.keys())
    return textwrap.dedent(f'''\
        """Auto-generated specimen rules — family-specific detections from enrichment pipeline.

        Families: {{families_list}}
        Generated from corpus of {{total}} samples. Review before committing.
        """

        from binanalysis.rules import Rule

        GENERATED_SPECIMEN_RULES: list[Rule] = [
        {{rules_block}}
        ]
    ''').replace("{total}", str(total)).replace("{families_list}", families_list).replace("{rules_block}", rules_block)


def generate_ioc_extractors(report: dict) -> str:
    """Generate IOC extractors for new string pattern categories."""
    cands = report.get("enrichment_candidates", {})
    domains = cands.get("recurring_c2_domains", [])

    if not domains:
        return ""

    # Build a domain list for a bulk IOC extractor
    domain_list = [entry["domain"] for entry in domains[:50]]
    domain_repr = repr(domain_list)

    return textwrap.dedent(f'''\
        """Auto-generated IOC extractors from enrichment pipeline.

        Review before committing. Merge useful extractors into ioc.py.
        """

        from binanalysis.rules import IOCExtractor

        _KNOWN_C2_DOMAINS = {{domain_list}}

        GENERATED_IOC_EXTRACTORS: list[IOCExtractor] = [
            IOCExtractor("c2_domains", "Known C2 Domains (corpus)", "danger",
                         lambda ctx: [
                             i["value"] for i in ctx.string_findings.get("domain", [])
                             if any(d in i["value"] for d in _KNOWN_C2_DOMAINS)
                         ]),

            IOCExtractor("gen_c2_urls", "C2 URL Patterns (corpus)", "warn",
                         lambda ctx: [
                             i["value"] for i in ctx.string_findings.get("url", [])
                             if any(d in i["value"] for d in _KNOWN_C2_DOMAINS)
                         ]),
        ]
    ''').replace("{domain_list}", domain_repr)


def main():
    parser = argparse.ArgumentParser(description="Auto-generate detection rules from enrichment report")
    parser.add_argument("--report", type=Path, default=REPORT_DEFAULT,
                        help=f"Enrichment report JSON (default: {REPORT_DEFAULT})")
    parser.add_argument("--min-pct", type=float, default=10.0,
                        help="Minimum corpus prevalence %% to generate a rule (default: 10)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print generated code to stdout instead of writing files")
    args = parser.parse_args()

    with open(args.report) as f:
        report = json.load(f)

    total = report["meta"]["total_samples"]
    print(f"[*] Loaded enrichment report ({total} samples)")

    outputs: list[tuple[Path, str, str]] = []

    rules_code = generate_rules(report, args.min_pct)
    if rules_code:
        outputs.append((RULES_OUT, rules_code, "behavioral rules"))

    specimen_code = generate_specimen_rules(report)
    if specimen_code:
        outputs.append((SPECIMEN_OUT, specimen_code, "specimen rules"))

    patterns_code = generate_patterns(report)
    if patterns_code:
        outputs.append((PATTERNS_OUT, patterns_code, "string patterns"))

    ioc_code = generate_ioc_extractors(report)
    if ioc_code:
        outputs.append((IOC_OUT, ioc_code, "IOC extractors"))

    if not outputs:
        print("[*] No new rules/patterns to generate — corpus coverage looks good")
        return

    for path, code, label in outputs:
        if args.dry_run:
            print(f"\n{'='*60}")
            print(f"  {label} → {path}")
            print(f"{'='*60}")
            print(code)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(code)
            print(f"  [+] Generated {label} → {path}")

    if not args.dry_run:
        print(f"\n[*] Done — generated files are auto-loaded by the engine.")
        print(f"    Review before committing, then re-run batch analysis to verify coverage.")


if __name__ == "__main__":
    main()
