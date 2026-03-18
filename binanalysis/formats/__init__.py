"""Format detection and registry."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from binanalysis.context import AnalysisContext

@dataclass
class FormatHandler:
    """A pluggable binary format backend."""
    name: str
    magic_check: Callable[[bytes], bool]
    analyze: Callable[[Path, bytes, dict], "AnalysisContext"]
    get_rules: Callable[[], list]

FORMATS: list[FormatHandler] = []

def register_format(handler: FormatHandler):
    """Register a format handler."""
    FORMATS.append(handler)

def detect_format(data: bytes) -> FormatHandler | None:
    """Auto-detect binary format from magic bytes."""
    return next((f for f in FORMATS if f.magic_check(data)), None)
