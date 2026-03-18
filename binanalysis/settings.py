"""Settings management — CLI args + TOML config file."""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from pathlib import Path

try:
    import tomllib  # Python 3.11+
except ImportError:
    try:
        import tomli as tomllib  # fallback
    except ImportError:
        tomllib = None


DEFAULT_CONFIG_PATHS = [
    Path("binanalysis.toml"),
    Path.home() / ".config" / "binanalysis" / "config.toml",
]

_DEFAULT_CONFIG_CONTENT = """\
# binanalysis configuration — edit to customize defaults
# Generated on first run. All values here are overridable via CLI flags.

[paths]
# Where capa rules are stored (auto-downloaded here if missing)
capa_rules = "{capa_rules}"
# capa rules git repo (change to a mirror or fork if needed)
capa_rules_repo = "https://github.com/mandiant/capa-rules.git"
# Where community YARA rules are stored (fetched via --update-yara)
yara_community_dir = "{yara_rules}"
# Additional YARA rule directories scanned on every run (list of paths)
# yara_extra_dirs = ["/path/to/rules"]
# Path to Ghidra headless analyzer (auto-discovered if empty)
# ghidra_headless = ""

# Community YARA repos cloned/updated by --update-yara.
# subdir = subdirectory within the repo that contains .yar files ("." = repo root).
# Comment out or remove any repos you don't want.

[yara_repos.signature-base]
repo = "https://github.com/Neo23x0/signature-base.git"
subdir = "yara"
description = "Cobalt Strike, Go implants, webshells (Neo23x0)"

[yara_repos.yara-rules]
repo = "https://github.com/Yara-Rules/rules.git"
subdir = "."
description = "Broad malware families, packers, exploits"

[yara_repos.gcti]
repo = "https://github.com/chronicle/GCTI.git"
subdir = "YARA"
description = "APT-focused, high quality (Google)"

[yara_repos.reversinglabs]
repo = "https://github.com/reversinglabs/reversinglabs-yara-rules.git"
subdir = "yara"
description = "Large malware family signature set"

[yara_repos.eset]
repo = "https://github.com/eset/malware-ioc.git"
subdir = "."
description = "ESET research publications"

[yara_repos.elastic]
repo = "https://github.com/elastic/protections-artifacts.git"
subdir = "yara/rules"
description = "Elastic threat research"

[features]
capa = false  # opt-in via --capa flag (slow, downloads ~100MB rules on first use)
yara = false  # opt-in via --yara flag (auto-downloads community rules on first use)
# decompile = ""  # "", "r2", "ghidra", or "both"

[output]
no_color = false
quiet = false
json = false

[llm]
url = "http://localhost:11434"
model = "llama3"
timeout = 300
report = false
"""

_DEFAULT_CAPA_RULES = Path.home() / ".local" / "share" / "binanalysis" / "capa-rules"
_DEFAULT_YARA_RULES = Path.home() / ".local" / "share" / "binanalysis" / "yara-rules"


def _ensure_default_config() -> None:
    """Write default config to ~/.config/binanalysis/config.toml if it doesn't exist."""
    config_path = Path.home() / ".config" / "binanalysis" / "config.toml"
    if config_path.exists():
        return
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(
        _DEFAULT_CONFIG_CONTENT.format(
            capa_rules=str(_DEFAULT_CAPA_RULES),
            yara_rules=str(_DEFAULT_YARA_RULES),
        )
    )
    from binanalysis.output import info
    info(f"Created default config: {config_path}")


@dataclass
class Settings:
    # Paths
    capa_rules: Path = _DEFAULT_CAPA_RULES
    capa_rules_repo: str = "https://github.com/mandiant/capa-rules.git"
    yara_community_dir: Path = _DEFAULT_YARA_RULES
    yara_repos: dict = field(default_factory=lambda: {
        "signature-base": {"repo": "https://github.com/Neo23x0/signature-base.git", "subdir": "yara"},
        "yara-rules":     {"repo": "https://github.com/Yara-Rules/rules.git", "subdir": "."},
        "gcti":           {"repo": "https://github.com/chronicle/GCTI.git", "subdir": "YARA"},
        "reversinglabs":  {"repo": "https://github.com/reversinglabs/reversinglabs-yara-rules.git", "subdir": "yara"},
        "eset":           {"repo": "https://github.com/eset/malware-ioc.git", "subdir": "."},
        "elastic":        {"repo": "https://github.com/elastic/protections-artifacts.git", "subdir": "yara/rules"},
    })
    yara_extra_dirs: list[Path] = field(default_factory=list)
    ghidra_headless: str = ""  # empty = auto-discover

    # Feature toggles
    run_capa: bool = False
    run_yara: bool = False
    run_decompile: str = ""  # "", "r2", "ghidra", "both"

    # Output
    no_color: bool = False
    quiet: bool = False
    save_json: bool = False

    # LLM report
    llm_url: str = "http://localhost:11434"
    llm_model: str = "llama3"
    llm_timeout: int = 300
    run_report: bool = False
    debug: bool = False


def load_config(config_path: Path | None = None) -> dict:
    """Load config from TOML file. Returns empty dict if not found or tomllib unavailable."""
    if tomllib is None:
        return {}

    paths = [config_path] if config_path else DEFAULT_CONFIG_PATHS
    for p in paths:
        if p and p.exists():
            with open(p, "rb") as f:
                return tomllib.load(f)
    return {}


def parse_args():
    parser = argparse.ArgumentParser(
        prog="binanalysis",
        description="Binary Analysis Toolkit (BAT) — PE static analysis with behavioral rules, capa, YARA, and decompiler integration",
    )
    parser.add_argument("file", type=Path, help="PE binary to analyze")
    parser.add_argument("--json", action="store_true", help="Save JSON report alongside binary")
    parser.add_argument(
        "--decompile",
        choices=["r2", "ghidra", "both"],
        help="Decompile with r2pipe, Ghidra, or both",
    )
    parser.add_argument("--capa", action="store_true", help="Run capa capability detection (slow, auto-downloads rules on first use)")
    parser.add_argument("--yara", action="store_true", help="Run YARA signature scan (auto-downloads community rules on first use)")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--quiet", action="store_true", help="Only show verdict and critical findings")
    parser.add_argument("--config", type=Path, help="Path to config TOML file")
    parser.add_argument("--capa-rules", type=Path, help="Path to capa rules directory")
    parser.add_argument("--yara-rules", type=Path, nargs="+", help="Additional YARA rule directories")
    parser.add_argument("--report", action="store_true", help="Generate LLM-powered analyst report (requires Ollama or compatible API)")
    parser.add_argument("--llm-url", type=str, help="LLM API base URL (default: http://localhost:11434)")
    parser.add_argument("--llm-model", type=str, help="LLM model name (default: llama3)")
    parser.add_argument("--llm-timeout", type=int, help="LLM request timeout in seconds (default: 300)")
    parser.add_argument("--debug", action="store_true", help="Save LLM prompt to file for inspection")
    parser.add_argument("--update-yara", action="store_true", help="Download/update community YARA rule repos before scanning")
    parser.add_argument("--update-capa", action="store_true", help="Download/update capa rules before scanning")
    return parser.parse_args()


def build_settings(args) -> Settings:
    """Merge CLI args over config file defaults."""
    _ensure_default_config()
    config = load_config(getattr(args, "config", None))

    paths_cfg = config.get("paths", {})
    output_cfg = config.get("output", {})
    features_cfg = config.get("features", {})
    llm_cfg = config.get("llm", {})

    settings = Settings(
        # Paths — CLI overrides config
        capa_rules=Path(
            getattr(args, "capa_rules", None)
            or paths_cfg.get("capa_rules", str(_DEFAULT_CAPA_RULES))
        ).expanduser(),
        capa_rules_repo=paths_cfg.get("capa_rules_repo", "https://github.com/mandiant/capa-rules.git"),
        yara_community_dir=Path(
            paths_cfg.get("yara_community_dir", str(_DEFAULT_YARA_RULES))
        ).expanduser(),
        yara_repos=config.get("yara_repos", {
            "Yara-Rules": "https://github.com/Yara-Rules/rules.git",
            "reversinglabs": "https://github.com/reversinglabs/reversinglabs-yara-rules.git",
        }),
        yara_extra_dirs=[
            Path(d).expanduser()
            for d in (getattr(args, "yara_rules", None) or paths_cfg.get("yara_extra_dirs", []))
        ],
        ghidra_headless=paths_cfg.get("ghidra_headless", ""),

        # Features
        run_capa=getattr(args, "capa", False) or features_cfg.get("capa", False),
        run_yara=getattr(args, "yara", False) or features_cfg.get("yara", False),
        run_decompile=getattr(args, "decompile", None) or features_cfg.get("decompile", ""),

        # Output
        no_color=getattr(args, "no_color", False) or output_cfg.get("no_color", False),
        quiet=getattr(args, "quiet", False) or output_cfg.get("quiet", False),
        save_json=getattr(args, "json", False) or output_cfg.get("json", False),

        # LLM report
        llm_url=getattr(args, "llm_url", None) or llm_cfg.get("url", "http://localhost:11434"),
        llm_model=getattr(args, "llm_model", None) or llm_cfg.get("model", "llama3"),
        llm_timeout=getattr(args, "llm_timeout", None) or llm_cfg.get("timeout", 300),
        run_report=getattr(args, "report", False) or llm_cfg.get("report", False),
        debug=getattr(args, "debug", False),
    )

    # Apply no_color to output module
    if settings.no_color:
        from binanalysis.output import C
        C.RED = C.GREEN = C.YELLOW = C.BLUE = C.MAGENTA = C.CYAN = ""
        C.BOLD = C.RESET = ""

    return settings
