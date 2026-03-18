"""capa integration — capability detection with ATT&CK mapping."""

import io
import sys
import logging
from pathlib import Path

from binanalysis.output import heading, subheading, info, warn, detail

try:
    import capa.rules
    import capa.loader
    import capa.main
    HAS_CAPA = True
except ImportError:
    HAS_CAPA = False

DEFAULT_CAPA_RULES = Path("/tmp/capa-rules")


def run_capa_analysis(filepath: Path, rules_path: Path | None = None) -> list[dict]:
    """Run capa capability detection on a PE binary.
    Returns a list of capability dicts with name, ATT&CK mapping, and namespace."""
    if not HAS_CAPA:
        info("capa not installed — skipping capability detection (uv add flare-capa)")
        return []

    rules_path = rules_path or DEFAULT_CAPA_RULES
    if not rules_path.exists():
        warn(f"capa rules not found at {rules_path}")
        info("Download: git clone --depth 1 https://github.com/mandiant/capa-rules.git /tmp/capa-rules")
        return []

    heading("CAPA CAPABILITY DETECTION")

    logging.disable(logging.CRITICAL)
    old_stderr = sys.stderr
    sys.stderr = io.StringIO()

    try:
        ruleset = capa.rules.get_rules([rules_path], enable_cache=True)
        sigpaths = capa.loader.get_signatures(Path("/tmp"))
        extractor = capa.loader.get_extractor(
            filepath, capa.loader.FORMAT_PE, capa.loader.OS_AUTO,
            capa.loader.BACKEND_VIV, sigpaths, disable_progress=True,
        )
        caps = capa.main.find_capabilities(ruleset, extractor, disable_progress=True)
    except Exception as e:
        warn(f"capa analysis failed: {e}")
        return []
    finally:
        sys.stderr = old_stderr
        logging.disable(logging.NOTSET)

    results = []
    for rule_name, addresses in caps.matches.items():
        rule = ruleset.rules[rule_name]
        if rule.is_subscope_rule():
            continue

        att_ck = []
        for entry in rule.meta.get("att&ck", []):
            att_ck.append(str(entry.name) if hasattr(entry, "name") else str(entry))

        namespace = rule.meta.get("namespace", "")
        results.append({
            "name": rule_name,
            "namespace": namespace,
            "att&ck": att_ck,
        })

    # Display grouped by namespace
    by_ns = {}
    for r in results:
        ns = r["namespace"].split("/")[0] if r["namespace"] else "other"
        by_ns.setdefault(ns, []).append(r)

    for ns in sorted(by_ns):
        subheading(ns.replace("-", " ").title())
        for r in sorted(by_ns[ns], key=lambda x: x["name"]):
            att = f"  [{r['att&ck'][0]}]" if r["att&ck"] else ""
            info(f"{r['name']}{att}")

    detail("Total capabilities", str(len(results)))
    return results
