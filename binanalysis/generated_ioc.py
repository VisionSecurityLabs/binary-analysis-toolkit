"""Auto-generated IOC extractors from enrichment pipeline.

Review before committing. Merge useful extractors into ioc.py.
"""

from binanalysis.rules import IOCExtractor

_KNOWN_C2_DOMAINS = ['BreakingSecurity.net', 'geoplugin.net']

GENERATED_IOC_EXTRACTORS: list[IOCExtractor] = [
    IOCExtractor("c2_domains", "Known C2 Domains (corpus)", "danger",
                 lambda ctx: [
                     i["value"] for i in ctx.string_findings.get("domain", [])
                     if any(d in i["value"] for d in _KNOWN_C2_DOMAINS)
                 ]),

    IOCExtractor("gen_c2_urls", "C2 URL Patterns (corpus)", "warn",
                 lambda ctx: [
                     i["value"] for i in ctx.string_findings.get("url", [])
                     if any(d in i["value"] for d in _KNOWN_C2_DOMAINS)
                 ]),
]
