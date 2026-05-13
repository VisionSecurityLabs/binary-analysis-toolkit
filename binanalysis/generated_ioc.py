"""Auto-generated IOC extractors from enrichment pipeline.

Review before committing. Merge useful extractors into ioc.py.
"""

from urllib.parse import urlparse

from binanalysis.rules import IOCExtractor
from binanalysis.ioc import _is_benign_domain

_KNOWN_C2_DOMAINS = ['ip-api.com']


def _matches_known_domain(value: str) -> bool:
    domain = value.lower()
    if "://" in domain:
        domain = (urlparse(domain).hostname or "").lower()
    if not domain or _is_benign_domain(domain):
        return False
    return any(domain == d or domain.endswith("." + d) for d in _KNOWN_C2_DOMAINS)

GENERATED_IOC_EXTRACTORS: list[IOCExtractor] = [
    IOCExtractor("c2_domains", "Known C2 Domains (corpus)", "danger",
                 lambda ctx: [
                     i["value"] for i in ctx.string_findings.get("domain", [])
                     if _matches_known_domain(i["value"])
                 ]),

    IOCExtractor("gen_c2_urls", "C2 URL Patterns (corpus)", "warn",
                 lambda ctx: [
                     i["value"] for i in ctx.string_findings.get("url", [])
                     if _matches_known_domain(i["value"])
                 ]),
]
