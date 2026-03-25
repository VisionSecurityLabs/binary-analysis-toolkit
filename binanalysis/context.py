"""AnalysisContext — base class for all format-specific contexts."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass
class AnalysisContext:
    """Shared analysis data passed to every rule and extractor.

    Format-specific backends subclass this and add their own fields.
    """
    filepath: Path
    data: bytes
    format_name: str
    ascii_strings: set[str]
    wide_strings: set[str]
    all_strings: set[str]
    string_findings: dict              # category -> [{"value":…, "encoding":…, …}]
    sections: list[dict]               # name, entropy, size, characteristics
    hashes: dict                       # md5, sha1, sha256

    # ── convenience predicates (format-agnostic) ──

    def has_string_containing(self, substring: str) -> bool:
        return any(substring in s for s in self.all_strings)

    def has_finding(self, category: str) -> bool:
        return bool(self.string_findings.get(category))

    def finding_count(self, category: str) -> int:
        return len(self.string_findings.get(category, []))

    def any_section(self, predicate) -> bool:
        return any(predicate(s) for s in self.sections)
