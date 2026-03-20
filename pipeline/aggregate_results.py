"""
Aggregate binanalysis JSON reports across a corpus of malware samples.

Produces an enrichment report highlighting:
  - Rule coverage: which behavioral rules fire on what % of samples
  - Detection gaps: import combinations common in the corpus but uncovered by any rule
  - String candidates: recurring URL patterns, registry keys, mutex names
  - IOC clusters: common domains/IPs seen across samples

Usage:
    python pipeline/aggregate_results.py
    python pipeline/aggregate_results.py --reports samples/ --output enrichment.json
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

# ── Patterns mined from existing rule definitions ──────────────────────────
# These are the import combinations already covered. Used to avoid suggesting
# rules that already exist.
COVERED_IMPORT_COMBOS = [
    {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"},
    {"QueueUserAPC"},
    {"CreateRemoteThread", "LoadLibraryA"},
    {"CreateRemoteThread", "LoadLibraryW"},
    {"IsDebuggerPresent"},
    {"CheckRemoteDebuggerPresent"},
    {"NtQueryInformationProcess"},
    {"OpenProcessToken", "AdjustTokenPrivileges"},
    {"CredEnumerateA"},
    {"CredEnumerateW"},
    {"WinHttpOpen", "WinHttpConnect"},
    {"InternetOpenA"},
    {"InternetOpenW"},
    {"URLDownloadToFileA"},
    {"URLDownloadToFileW"},
    {"WSAStartup", "connect"},
    {"GetProcAddress", "LoadLibraryA"},
    {"GetProcAddress", "LoadLibraryW"},
    {"CreateServiceA"},
    {"CreateServiceW"},
]


def _flat_imports(report: dict) -> set[str]:
    """Flatten the imports dict (dll → [funcs]) into a set of function names."""
    imports = report.get("format_specific", {}).get("imports", {})
    result: set[str] = set()
    for funcs in imports.values():
        result.update(f for f in funcs if isinstance(f, str))
    return result


def _string_values(report: dict) -> list[str]:
    """Flatten all extracted string values from the report."""
    strings = report.get("generic", {}).get("strings", {})
    result = []
    for category_items in strings.values():
        for item in category_items:
            if isinstance(item, dict):
                result.append(item.get("value", ""))
            elif isinstance(item, str):
                result.append(item)
    return result


def _is_covered(imports: set[str]) -> bool:
    """Return True if this import set is already matched by an existing rule."""
    for combo in COVERED_IMPORT_COMBOS:
        if combo.issubset(imports):
            return True
    return False


# ── TODO: Implement this function ─────────────────────────────────────────
# This is the core analytical decision: given a pattern that appears in
# `count` out of `total` samples, should we surface it as a detection candidate?
#
# Trade-offs to consider:
#   - High threshold (e.g. >50%): low noise, but only catches dominant families.
#     Good for "common malware" rules but may miss targeted/niche techniques.
#   - Low threshold (e.g. >5%): catches more techniques but risks false positives
#     if legitimate software uses the same APIs.
#   - `pattern_type` lets you differentiate: strings need tighter thresholds
#     (too common in benign software) vs. import combos (more distinctive).
#
# Suggested approach: start loose (5–10%) and tighten after reviewing FP rate.
#
def should_suggest(count: int, total: int, pattern_type: str) -> bool:
    """
    Return True if this pattern appears often enough to suggest as a new rule.

    Args:
        count: number of samples where the pattern was observed
        total: total number of analyzed samples
        pattern_type: one of "import_combo", "string_url", "string_registry",
                      "string_mutex", "ioc_domain", "ioc_ip"

    Returns:
        bool: True to include this pattern in the enrichment report
    """
    if total == 0 or count < 2:
        return False
    pct = 100 * count / total
    thresholds = {
        "import_combo": 5,
        "string_url": 10,
        "string_registry": 10,
        "string_mutex": 15,
        "ioc_domain": 5,
        "ioc_ip": 10,
    }
    return pct >= thresholds.get(pattern_type, 10)


# ──────────────────────────────────────────────────────────────────────────


def load_reports(samples_dir: Path) -> list[dict]:
    reports = []
    for path in sorted(samples_dir.glob("*_analysis.json")):
        try:
            with open(path) as f:
                data = json.load(f)
            data["_source_file"] = str(path)
            reports.append(data)
        except Exception as e:
            print(f"  [!] Could not read {path.name}: {e}")
    return reports


def aggregate(reports: list[dict]) -> dict:
    total = len(reports)
    if total == 0:
        return {"meta": {"total_samples": 0}, "rule_coverage": [], "enrichment_candidates": {}}
    print(f"[*] Aggregating {total} reports…")

    # ── Rule coverage ──────────────────────────────────────────────────────
    rule_hits: Counter[str] = Counter()
    for r in reports:
        for behavior in r.get("behavior", {}).get("behaviors", []):
            rule_hits[behavior.get("rule_id", behavior.get("description", "?"))] += 1

    # ── Import analysis ────────────────────────────────────────────────────
    # Single-function frequency
    api_freq: Counter[str] = Counter()
    # Pair frequency (for combo rule suggestions)
    pair_freq: Counter[tuple] = Counter()

    # APIs worth tracking for combo-rule suggestions (process, injection, network, crypto)
    _SUSPICIOUS_PREFIXES = (
        "Virtual", "NtMap", "NtWrite", "NtCreate", "NtOpen", "NtAllocate",
        "CreateRemote", "QueueUser", "SetThread", "WriteProcess", "ReadProcess",
        "CreateProcess", "WinExec", "ShellExecute",
        "Crypt", "BCrypt",
        "WSA", "connect", "send", "recv", "Internet", "HttpSend", "WinHttp",
        "URLDownload",
        "RegOpen", "RegSet", "RegCreate",
        "OpenProcess", "AdjustToken", "LookupPrivilege",
        "GetProcAddress", "LoadLibrary",
    )

    for r in reports:
        imports = _flat_imports(r)
        api_freq.update(imports)
        suspicious_apis = [
            a for a in imports
            if any(a.startswith(p) for p in _SUSPICIOUS_PREFIXES)
        ]
        for i, a in enumerate(suspicious_apis):
            for b in suspicious_apis[i + 1 :]:
                pair_freq[tuple(sorted([a, b]))] += 1

    # ── String pattern mining ──────────────────────────────────────────────
    url_pattern = re.compile(r"https?://[^\s\"'<>]{4,}", re.IGNORECASE)
    registry_pattern = re.compile(r"(?:HKEY_|HKLM|HKCU|SOFTWARE\\)[^\s\"'<>]{4,}", re.IGNORECASE)
    mutex_candidates: Counter[str] = Counter()
    url_candidates: Counter[str] = Counter()
    registry_candidates: Counter[str] = Counter()

    for r in reports:
        for s in _string_values(r):
            if url_pattern.search(s):
                # Normalize to domain+path prefix only
                url_candidates[s[:80]] += 1
            if registry_pattern.search(s):
                registry_candidates[s[:80]] += 1
            # Mutex heuristic: strings that look like mutex names (mixed case/digits,
            # not common words or API names ending in A/W/Ex)
            if (6 <= len(s) <= 32
                    and re.match(r"^[A-Za-z0-9_\-]{6,32}$", s)
                    and re.search(r"[a-z]", s) and re.search(r"[A-Z]", s)
                    and not s.endswith((".dll", ".exe", ".sys"))
                    and not re.match(r"^(?:Nt|Zw|Rtl|Ldr|Get|Set|Create|Open|Close|Read|Write|Delete)", s)):
                mutex_candidates[s] += 1

    # ── IOC clustering ─────────────────────────────────────────────────────
    domain_freq: Counter[str] = Counter()
    ip_freq: Counter[str] = Counter()
    ip_re = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|1?\d\d?)\b")

    for r in reports:
        iocs = r.get("iocs", {})
        for domain in iocs.get("domains", []):
            domain_freq[domain] += 1
        for entry in iocs.get("ips", []):
            val = entry if isinstance(entry, str) else entry.get("value", "")
            if val:
                ip_freq[val] += 1
        # Also mine raw strings for IPs not already in structured IOCs
        known_ips = set(iocs.get("ips", []))
        for s in _string_values(r):
            for ip in ip_re.findall(s):
                if ip not in known_ips and not ip.startswith(("127.", "0.", "255.", "10.", "192.168.")):
                    ip_freq[ip] += 1

    # ── Build enrichment candidates ────────────────────────────────────────
    gap_apis: list[dict] = []
    for api, count in api_freq.most_common(50):
        if not _is_covered({api}) and should_suggest(count, total, "import_combo"):
            gap_apis.append({"api": api, "count": count, "pct": round(100 * count / total, 1)})

    gap_pairs: list[dict] = []
    for (a, b), count in pair_freq.most_common(100):
        if not _is_covered({a, b}) and should_suggest(count, total, "import_combo"):
            gap_pairs.append({"pair": [a, b], "count": count, "pct": round(100 * count / total, 1)})

    url_hits = [
        {"pattern": u, "count": c, "pct": round(100 * c / total, 1)}
        for u, c in url_candidates.most_common(20)
        if should_suggest(c, total, "string_url")
    ]
    reg_hits = [
        {"pattern": r, "count": c, "pct": round(100 * c / total, 1)}
        for r, c in registry_candidates.most_common(20)
        if should_suggest(c, total, "string_registry")
    ]
    domain_hits = [
        {"domain": d, "count": c, "pct": round(100 * c / total, 1)}
        for d, c in domain_freq.most_common(20)
        if should_suggest(c, total, "ioc_domain")
    ]

    return {
        "meta": {"total_samples": total},
        "rule_coverage": [
            {"rule": rule, "count": count, "pct": round(100 * count / total, 1)}
            for rule, count in rule_hits.most_common()
        ],
        "enrichment_candidates": {
            "uncovered_single_apis": gap_apis,
            "uncovered_api_pairs": gap_pairs[:30],
            "recurring_urls": url_hits,
            "recurring_registry_keys": reg_hits,
            "recurring_c2_domains": domain_hits,
        },
    }


def print_summary(report: dict) -> None:
    total = report["meta"]["total_samples"]
    print(f"\n{'='*60}")
    print(f"  ENRICHMENT REPORT  ({total} samples)")
    print(f"{'='*60}")

    print("\n── Rule Coverage ─────────────────────────────────────────")
    for r in report["rule_coverage"][:15]:
        bar = "█" * int(r["pct"] / 5)
        print(f"  {r['rule']:40s} {r['count']:4d} ({r['pct']:5.1f}%)  {bar}")

    cands = report["enrichment_candidates"]

    if cands["uncovered_single_apis"]:
        print("\n── Uncovered Single APIs (new rule candidates) ───────────")
        for c in cands["uncovered_single_apis"][:10]:
            print(f"  {c['api']:45s} {c['count']:4d} ({c['pct']:5.1f}%)")

    if cands["uncovered_api_pairs"]:
        print("\n── Uncovered API Pairs (combo rule candidates) ───────────")
        for c in cands["uncovered_api_pairs"][:10]:
            print(f"  {c['pair'][0]} + {c['pair'][1]}")
            print(f"    → {c['count']} samples ({c['pct']}%)")

    if cands["recurring_urls"]:
        print("\n── Recurring URL Patterns ────────────────────────────────")
        for c in cands["recurring_urls"][:5]:
            print(f"  [{c['count']}]  {c['pattern'][:70]}")

    if cands["recurring_c2_domains"]:
        print("\n── Recurring C2 Domains ──────────────────────────────────")
        for c in cands["recurring_c2_domains"][:10]:
            print(f"  [{c['count']:3d}] {c['domain']}")


def main():
    parser = argparse.ArgumentParser(description="Aggregate binanalysis reports for detection enrichment")
    parser.add_argument("--reports", type=Path, default=Path("samples"),
                        help="Directory containing *_analysis.json files (default: samples/)")
    parser.add_argument("--output", type=Path, default=Path("enrichment_report.json"),
                        help="Output JSON path (default: enrichment_report.json)")
    args = parser.parse_args()

    reports = load_reports(args.reports)
    if not reports:
        print(f"[!] No *_analysis.json files found in {args.reports}")
        return

    enrichment = aggregate(reports)
    print_summary(enrichment)

    with open(args.output, "w") as f:
        json.dump(enrichment, f, indent=2)
    print(f"\n[*] Full report → {args.output}")


if __name__ == "__main__":
    main()
