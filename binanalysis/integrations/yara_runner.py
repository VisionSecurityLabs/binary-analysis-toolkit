"""YARA integration — signature scanning with peframe's bundled rules + custom directories."""

import sys
from pathlib import Path

from binanalysis.output import heading, info, warn, detail

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
    if extra_dirs:
        rule_dirs.extend(d for d in extra_dirs if d.exists())

    if not rule_dirs:
        warn("No YARA rule directories found")
        return []

    results = []
    for rule_dir in rule_dirs:
        for yar_file in sorted(rule_dir.glob("*.yar*")):
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
