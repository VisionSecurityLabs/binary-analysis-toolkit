"""YARA integration — signature scanning with peframe's bundled rules + custom directories."""

import shutil
import subprocess
import sys
from pathlib import Path

from bat_analyzer.output import heading, info, warn, detail

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

COMMUNITY_YARA_DIR = Path.home() / ".bat_analyzer" / "yara_rules"

COMMUNITY_REPOS = [
    ("https://github.com/Yara-Rules/rules.git", "Yara-Rules"),
    ("https://github.com/reversinglabs/reversinglabs-yara-rules.git", "reversinglabs"),
]


def download_community_rules() -> list[Path]:
    """Clone or update community YARA rule repositories into COMMUNITY_YARA_DIR.

    Does NOT run automatically on each scan — call this explicitly to fetch/refresh rules.
    Returns the list of directories that were successfully cloned or updated.
    """
    if not shutil.which("git"):
        warn("git not found in PATH — cannot download community YARA rules")
        return []

    COMMUNITY_YARA_DIR.mkdir(parents=True, exist_ok=True)

    available: list[Path] = []
    for url, name in COMMUNITY_REPOS:
        target_dir = COMMUNITY_YARA_DIR / name
        try:
            if target_dir.exists():
                info(f"Updating community rules: {name}")
                result = subprocess.run(
                    ["git", "-C", str(target_dir), "pull", "--ff-only"],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                if result.returncode != 0:
                    warn(f"Failed to update {name}: {result.stderr.strip()}")
                    continue
            else:
                info(f"Cloning community rules: {name}")
                result = subprocess.run(
                    ["git", "clone", "--depth", "1", url, str(target_dir)],
                    capture_output=True,
                    text=True,
                    timeout=300,
                )
                if result.returncode != 0:
                    warn(f"Failed to clone {name}: {result.stderr.strip()}")
                    continue
            available.append(target_dir)
        except subprocess.TimeoutExpired:
            warn(f"Timed out while processing {name}")
        except Exception as exc:  # noqa: BLE001
            warn(f"Unexpected error for {name}: {exc}")

    return available


def run_yara_scan(data: bytes, extra_dirs: list[Path] | None = None) -> list[dict]:
    """Scan binary with YARA rules from peframe + any custom directories.
    Returns list of match dicts with rule name, tags, and source file."""
    if not HAS_YARA:
        info("yara-python not installed — skipping signature scan (uv add yara-python)")
        return []

    heading("YARA SIGNATURE SCAN")

    rule_dirs = []
    if PEFRAME_YARA_DIR.exists():
        rule_dirs.append(PEFRAME_YARA_DIR)
    if DEFAULT_YARA_DIR.exists():
        rule_dirs.append(DEFAULT_YARA_DIR)
    if COMMUNITY_YARA_DIR.exists():
        rule_dirs.extend(
            d for d in COMMUNITY_YARA_DIR.iterdir() if d.is_dir()
        )
    if extra_dirs:
        rule_dirs.extend(d for d in extra_dirs if d.exists())

    if not rule_dirs:
        warn("No YARA rule directories found")
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
