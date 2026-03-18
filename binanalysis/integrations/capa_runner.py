"""capa integration — capability detection with ATT&CK mapping."""

import io
import shutil
import subprocess
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

from binanalysis.settings import _DEFAULT_CAPA_RULES
DEFAULT_CAPA_RULES = _DEFAULT_CAPA_RULES

_DEFAULT_CAPA_REPOS: dict = {
    "capa-rules": {"repo": "https://github.com/mandiant/capa-rules.git"},
}


def update_capa_rules(rules_path: Path | None = None, repos: dict | None = None) -> bool:
    """Clone or pull capa rule repos into rules_path. Returns True if all succeeded."""
    target_base = rules_path or DEFAULT_CAPA_RULES
    repo_map = repos if repos else _DEFAULT_CAPA_REPOS

    if not shutil.which("git"):
        warn("git not found in PATH — cannot download capa rules")
        return False

    target_base.parent.mkdir(parents=True, exist_ok=True)
    success = True

    for name, meta in repo_map.items():
        url = meta["repo"] if isinstance(meta, dict) else meta
        desc = meta.get("description", "") if isinstance(meta, dict) else ""
        label = f"{name}  ({desc})" if desc else name
        target_dir = target_base  # capa uses a single rules dir, not per-repo subdirs

        if target_dir.exists():
            info(f"Updating: {label}")
            result = subprocess.run(
                ["git", "-C", str(target_dir), "pull", "--ff-only"],
                capture_output=True, text=True, timeout=120,
            )
        else:
            info(f"Cloning: {label}")
            result = subprocess.run(
                ["git", "clone", "--depth", "1", url, str(target_dir)],
                capture_output=True, text=True,
            )

        if result.returncode != 0:
            warn(f"Failed {name}: {result.stderr.strip()}")
            success = False
        else:
            info(f"capa rules up to date: {label}")

    return success


def run_capa_analysis(filepath: Path, rules_path: Path | None = None,
                      repos: dict | None = None) -> list[dict]:
    """Run capa capability detection on a PE binary.
    Returns a list of capability dicts with name, ATT&CK mapping, and namespace."""
    if not HAS_CAPA:
        info("capa not installed — skipping capability detection (uv add flare-capa)")
        return []

    rules_path = rules_path or DEFAULT_CAPA_RULES
    if not rules_path.exists():
        info(f"capa rules not found at {rules_path} — downloading now...")
        if not update_capa_rules(rules_path, repos):
            repo_url = (repos or _DEFAULT_CAPA_REPOS).get(
                "capa-rules", {}).get("repo", "")
            info(f"Manual fix: git clone --depth 1 {repo_url} {rules_path}")
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
    for rule_name, _ in caps.matches.items():
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
