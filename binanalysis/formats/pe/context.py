"""PEContext — PE-specific analysis context."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from binanalysis.context import AnalysisContext

if TYPE_CHECKING:
    import pefile


@dataclass
class PEContext(AnalysisContext):
    """PE-specific context with imports, version info, and pefile object."""
    pe: pefile.PE = None
    imports: dict = None                # dll_name -> [func_names]
    flat_imports: set = field(default_factory=set)  # all import function names
    version_info: dict = field(default_factory=dict)
    dynamic_apis: list = field(default_factory=list)
    exports: list = field(default_factory=list)
    dotnet: dict = field(default_factory=dict)

    # ── PE-specific predicates ──

    def has_import(self, *names: str) -> bool:
        return bool(self.flat_imports & set(names))

    def has_all_imports(self, *names: str) -> bool:
        return set(names) <= self.flat_imports
