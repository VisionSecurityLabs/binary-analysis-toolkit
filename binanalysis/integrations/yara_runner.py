"""YARA integration — signature scanning with peframe's bundled rules + custom directories."""

import shutil
import subprocess
import sys
from pathlib import Path

from binanalysis.output import heading, info, warn, detail
from binanalysis.settings import _DEFAULT_YARA_RULES

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False

PEFRAME_YARA_DIR = (
    Path(sys.prefix) / "lib"
    / f"python{sys.version_info.major}.{sys.version_info.minor}"
    / "site-packages" / "peframe" / "signatures" / "yara_plugins" / "pe"
)
DEFAULT_YARA_DIR = Path(__file__).parent.parent / "yara_rules"
COMMUNITY_YARA_DIR = _DEFAULT_YARA_RULES

COMMUNITY_REPOS: dict = {
    "signature-base": {"repo": "https://github.com/Neo23x0/signature-base.git",           "subdir": "yara"},
    "yara-rules":     {"repo": "https://github.com/Yara-Rules/rules.git",                 "subdir": "."},
    "gcti":           {"repo": "https://github.com/chronicle/GCTI.git",                   "subdir": "YARA"},
    "reversinglabs":  {"repo": "https://github.com/reversinglabs/reversinglabs-yara-rules.git", "subdir": "yara"},
    "eset":           {"repo": "https://github.com/eset/malware-ioc.git",                 "subdir": "."},
    "elastic":        {"repo": "https://github.com/elastic/protections-artifacts.git",    "subdir": "yara/rules"},
}


def _scan_paths_for_repos(community_dir: Path, repos: dict) -> list[Path]:
    """Return the actual .yar scan directories for each cloned repo (applies subdir)."""
    paths = []
    for name, meta in repos.items():
        subdir = meta.get("subdir", ".") if isinstance(meta, dict) else "."
        scan_path = community_dir / name / subdir
        if scan_path.exists():
            paths.append(scan_path)
    return paths


def download_community_rules(community_dir: Path | None = None,
                             repos: dict | None = None) -> list[Path]:
    """Clone or update community YARA rule repositories.

    Does NOT run automatically on each scan — call via --update-yara to fetch/refresh.
    Returns the list of successfully cloned/updated repo directories.
    """
    target_base = community_dir or COMMUNITY_YARA_DIR
    repo_map = repos if repos else COMMUNITY_REPOS

    if not shutil.which("git"):
        warn("git not found in PATH — cannot download community YARA rules")
        return []

    target_base.mkdir(parents=True, exist_ok=True)

    available: list[Path] = []
    for name, meta in repo_map.items():
        url = meta["repo"] if isinstance(meta, dict) else meta
        desc = meta.get("description", "") if isinstance(meta, dict) else ""
        label = f"{name}  ({desc})" if desc else name
        target_dir = target_base / name
        try:
            if target_dir.exists():
                info(f"Updating: {label}")
                result = subprocess.run(
                    ["git", "-C", str(target_dir), "pull", "--ff-only"],
                    capture_output=True, text=True, timeout=120,
                )
                if result.returncode != 0:
                    warn(f"Failed to update {name}: {result.stderr.strip()}")
                    continue
            else:
                info(f"Cloning: {label}")
                result = subprocess.run(
                    ["git", "clone", "--depth", "1", url, str(target_dir)],
                    capture_output=True, text=True, timeout=300,
                )
                if result.returncode != 0:
                    warn(f"Failed to clone {name}: {result.stderr.strip()}")
                    continue
            available.append(target_dir)
        except subprocess.TimeoutExpired:
            warn(f"Timed out while processing {name}")
        except Exception as exc:
            warn(f"Unexpected error for {name}: {exc}")

    return available


def run_yara_scan(data: bytes, extra_dirs: list[Path] | None = None,
                  community_dir: Path | None = None,
                  repos: dict | None = None) -> list[dict]:
    """Scan binary with YARA rules from peframe + community dir + any custom directories.
    Returns list of match dicts with rule name, tags, and source file."""
    if not HAS_YARA:
        info("yara-python not installed — skipping signature scan (uv add yara-python)")
        return []

    heading("YARA SIGNATURE SCAN")

    community = community_dir or COMMUNITY_YARA_DIR
    repo_map = repos if repos else COMMUNITY_REPOS

    # Auto-download community rules on first use
    if not community.exists():
        info(f"Community rules not found at {community} — downloading now...")
        download_community_rules(community_dir=community, repos=repo_map)

    rule_dirs = []
    if PEFRAME_YARA_DIR.exists():
        rule_dirs.append(PEFRAME_YARA_DIR)
    if DEFAULT_YARA_DIR.exists():
        rule_dirs.append(DEFAULT_YARA_DIR)
    rule_dirs.extend(_scan_paths_for_repos(community, repo_map))
    if extra_dirs:
        rule_dirs.extend(d for d in extra_dirs if d.exists())

    if not rule_dirs:
        warn("No YARA rule directories found — download may have failed")
        return []

    results = []
    for rule_dir in rule_dirs:
        for yar_file in sorted(rule_dir.rglob("*.yar*")):
            try:
                rules = yara.compile(filepath=str(yar_file))
                matches = rules.match(data=data)
                for m in matches:
                    results.append({
                        "rule": m.rule,
                        "tags": list(m.tags),
                        "source": yar_file.name,
                    })
            except yara.Error:
                continue

    if results:
        for r in results:
            tag_str = f"  {r['tags']}" if r["tags"] else ""
            info(f"{r['rule']}{tag_str}  ({r['source']})")
    else:
        info("No YARA signature matches")

    detail("Total matches", str(len(results)))
    return results
