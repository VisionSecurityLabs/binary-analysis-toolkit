"""Rule engine — dataclasses and runner for behavioral rules and IOC extractors."""

import logging
from dataclasses import dataclass
from typing import Callable

from pe_analyzer.context import AnalysisContext
from pe_analyzer.output import heading, subheading, info, warn, danger, detail

logger = logging.getLogger(__name__)


@dataclass
class Rule:
    """A single behavioral detection rule."""
    name: str
    category: str
    severity: str          # critical | high | medium | low
    description: str
    check: Callable[[AnalysisContext], bool]


@dataclass
class IOCExtractor:
    """Pulls a specific IOC type from the analysis context."""
    name: str
    display: str           # human-readable label
    level: str             # danger | warn | info
    extract: Callable[[AnalysisContext], list[str]]


def run_behavioral_rules(ctx: AnalysisContext,
                         rules: list[Rule] | None = None) -> list[dict]:
    """Evaluate all rules against the context. Returns triggered findings."""
    from pe_analyzer.rules.generic import GENERIC_RULES
    from pe_analyzer.rules.specimen import SPECIMEN_RULES

    heading("BEHAVIORAL ANALYSIS")

    if rules is None:
        rules = GENERIC_RULES + SPECIMEN_RULES

    triggered = []
    for rule in rules:
        try:
            if rule.check(ctx):
                triggered.append({
                    "rule": rule.name,
                    "category": rule.category,
                    "severity": rule.severity,
                    "description": rule.description,
                })
        except Exception as e:
            logger.warning("Rule '%s' failed: %s", rule.name, e)

    if triggered:
        for t in triggered:
            printer = danger if t["severity"] in ("critical", "high") else warn
            printer(f"{t['category'].upper()}: {t['description']}")
    else:
        info("No clearly malicious behavioral patterns detected")

    return triggered


def run_ioc_extractors(ctx: AnalysisContext,
                       extractors: list[IOCExtractor] | None = None) -> dict:
    """Run all IOC extractors, display results, return structured dict."""
    from pe_analyzer.rules.ioc import IOC_EXTRACTORS

    heading("INDICATORS OF COMPROMISE (IOCs)")

    if extractors is None:
        extractors = IOC_EXTRACTORS

    printer_map = {"danger": danger, "warn": warn, "info": info}
    iocs = {}

    for ext in extractors:
        try:
            values = ext.extract(ctx)
        except Exception as e:
            logger.warning("IOC extractor '%s' failed: %s", ext.name, e)
            continue
        # deduplicate preserving order
        seen = set()
        deduped = []
        for v in values:
            if v not in seen:
                seen.add(v)
                deduped.append(v)
        if not deduped:
            continue
        iocs[ext.name] = deduped
        subheading(ext.display)
        printer = printer_map.get(ext.level, info)
        for v in deduped[:20]:
            printer(v)

    if ctx.version_info:
        iocs["version_info"] = ctx.version_info

    return iocs
