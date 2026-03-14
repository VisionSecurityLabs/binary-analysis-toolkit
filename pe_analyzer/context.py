"""AnalysisContext — the shared data bag passed to all rules, extractors, and integrations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    import pefile


@dataclass
class AnalysisContext:
    """Shared analysis data passed to every rule and extractor. Treat as read-only."""
    data: bytes
    pe: pefile.PE
    imports: dict                      # dll_name -> [func_names]
    flat_imports: set                   # all import function names
    string_findings: dict              # category -> [{"value":…, "encoding":…, …}]
    ascii_strings: set                 # deduplicated ascii string values
    wide_strings: set                  # deduplicated wide string values
    all_strings: set                   # ascii | wide
    sections: list
    version_info: dict
    dynamic_apis: list

    # ── convenience predicates ──

    def has_import(self, *names: str) -> bool:
        return bool(self.flat_imports & set(names))

    def has_all_imports(self, *names: str) -> bool:
        return set(names) <= self.flat_imports

    def has_string_containing(self, substring: str) -> bool:
        return any(substring in s for s in self.all_strings)

    def has_finding(self, category: str) -> bool:
        return bool(self.string_findings.get(category))

    def any_section(self, predicate) -> bool:
        return any(predicate(s) for s in self.sections)


def build_context(data: bytes, pe: pefile.PE, imports: dict, string_findings: dict,
                  sections: list, version_info: dict, dynamic_apis: list,
                  ascii_strs: set, wide_strs: set) -> AnalysisContext:
    """Assemble a context from individual analysis results."""
    flat = set()
    for funcs in imports.values():
        flat.update(funcs)
    return AnalysisContext(
        data=data, pe=pe,
        imports=imports, flat_imports=flat,
        string_findings=string_findings,
        ascii_strings=ascii_strs, wide_strings=wide_strs,
        all_strings=ascii_strs | wide_strs,
        sections=sections, version_info=version_info,
        dynamic_apis=dynamic_apis,
    )
