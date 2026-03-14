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
    Path("bat_analyzer.toml"),
    Path.home() / ".config" / "bat_analyzer" / "config.toml",
]


@dataclass
class Settings:
    # Paths
    capa_rules: Path = Path("/tmp/capa-rules")
    yara_extra_dirs: list[Path] = field(default_factory=list)
    ghidra_headless: str = ""  # empty = auto-discover

    # Feature toggles
    run_capa: bool = True
    run_yara: bool = True
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
        prog="bat-analyzer",
        description="Binary Analysis Toolkit (BAT) — PE static analysis with behavioral rules, capa, YARA, and decompiler integration",
    )
    parser.add_argument("file", type=Path, help="PE binary to analyze")
    parser.add_argument("--json", action="store_true", help="Save JSON report alongside binary")
    parser.add_argument(
        "--decompile",
        choices=["r2", "ghidra", "both"],
        help="Decompile with r2pipe, Ghidra, or both",
    )
    parser.add_argument("--no-capa", action="store_true", help="Skip capa analysis")
    parser.add_argument("--no-yara", action="store_true", help="Skip YARA scan")
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
    return parser.parse_args()


def build_settings(args) -> Settings:
    """Merge CLI args over config file defaults."""
    config = load_config(getattr(args, "config", None))

    paths_cfg = config.get("paths", {})
    output_cfg = config.get("output", {})
    features_cfg = config.get("features", {})
    llm_cfg = config.get("llm", {})

    settings = Settings(
        # Paths — CLI overrides config
        capa_rules=Path(
            getattr(args, "capa_rules", None) or paths_cfg.get("capa_rules", "/tmp/capa-rules")
        ),
        yara_extra_dirs=[
            Path(d)
            for d in (getattr(args, "yara_rules", None) or paths_cfg.get("yara_extra_dirs", []))
        ],
        ghidra_headless=paths_cfg.get("ghidra_headless", ""),

        # Features
        run_capa=not getattr(args, "no_capa", False) and features_cfg.get("capa", True),
        run_yara=not getattr(args, "no_yara", False) and features_cfg.get("yara", True),
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
        from bat_analyzer.output import C
        C.RED = C.GREEN = C.YELLOW = C.BLUE = C.MAGENTA = C.CYAN = ""
        C.BOLD = C.RESET = ""

    return settings
