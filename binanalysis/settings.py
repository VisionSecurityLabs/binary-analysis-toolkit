"""Settings management — CLI args + YAML config file."""

from __future__ import annotations

import argparse
import importlib.resources
import shutil
from dataclasses import dataclass, field
from pathlib import Path

import yaml


DEFAULT_CONFIG_PATHS = [
    Path("binanalysis.yaml"),
    Path.home() / ".config" / "binanalysis" / "config.yaml",
]

_DEFAULT_CAPA_RULES = Path.home() / ".local" / "share" / "binanalysis" / "capa-rules"
_DEFAULT_YARA_RULES = Path.home() / ".local" / "share" / "binanalysis" / "yara-rules"


def _ensure_default_config() -> None:
    """Copy bundled config.default.yaml to ~/.config/binanalysis/config.yaml on first run."""
    config_path = Path.home() / ".config" / "binanalysis" / "config.yaml"
    if config_path.exists():
        return
    config_path.parent.mkdir(parents=True, exist_ok=True)
    src = importlib.resources.files("binanalysis").joinpath("config.default.yaml")
    with importlib.resources.as_file(src) as p:
        shutil.copy(p, config_path)
    from binanalysis.output import info
    info(f"Created default config: {config_path}")


@dataclass
class Settings:
    # Paths
    capa_rules: Path = _DEFAULT_CAPA_RULES
    capa_repos: dict = field(default_factory=lambda: {
        "capa-rules": {"repo": "https://github.com/mandiant/capa-rules.git"},
    })
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
    """Load config from YAML file. Returns empty dict if not found."""
    paths = [config_path] if config_path else DEFAULT_CONFIG_PATHS
    for p in paths:
        if p and p.exists():
            with open(p) as f:
                return yaml.safe_load(f) or {}
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
    parser.add_argument("--config", type=Path, help="Path to config YAML file")
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
        capa_repos=config.get("capa_repos", {
            "capa-rules": {"repo": "https://github.com/mandiant/capa-rules.git"},
        }),
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
