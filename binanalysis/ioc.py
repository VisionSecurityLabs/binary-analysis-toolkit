"""IOC extractors — each pulls one category of indicators from the analysis context."""

from pathlib import Path

from binanalysis.rules import IOCExtractor

_DATA_DIR = Path(__file__).resolve().parent.parent / "data"


def _load_suspicious_subdomains() -> list[str]:
    """Load suspicious subdomain patterns for domain classification."""
    path = _DATA_DIR / "suspicious_subdomains.txt"
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text().splitlines()
            if line.strip() and not line.strip().startswith("#")]


_SUSPICIOUS_SUBDOMAINS = _load_suspicious_subdomains()


def _extract_suspicious_domains(ctx) -> list[str]:
    """Extract domains that match known suspicious subdomain patterns."""
    results = []
    for item in ctx.string_findings.get("domain", []):
        domain = item["value"]
        if any(sub in domain for sub in _SUSPICIOUS_SUBDOMAINS):
            results.append(domain)
    return results


IOC_EXTRACTORS: list[IOCExtractor] = [
    IOCExtractor("urls", "URLs", "warn",
                 lambda ctx: [i["value"] for i in ctx.string_findings.get("url", [])]),

    IOCExtractor("suspicious_domains", "Suspicious Domains (C2/hosting)", "warn",
                 _extract_suspicious_domains),

    IOCExtractor("domains", "Domains", "info",
                 lambda ctx: [i["value"] for i in ctx.string_findings.get("domain", [])]),

    IOCExtractor("credentials", "Embedded Credentials / Tokens", "danger",
                 lambda ctx: [i["value"][:60] + "\u2026" for i in
                              ctx.string_findings.get("github_pat", [])
                              + ctx.string_findings.get("github_token", [])
                              + ctx.string_findings.get("bearer_token", [])]),

    IOCExtractor("user_agents", "User-Agent Strings", "info",
                 lambda ctx: [i["value"] for i in ctx.string_findings.get("user_agent", [])]),

    IOCExtractor("windows_paths", "Windows File Paths", "info",
                 lambda ctx: [i["value"] for i in ctx.string_findings.get("windows_path", [])]),

    IOCExtractor("registry_keys", "Registry Keys", "warn",
                 lambda ctx: [i["value"] for i in ctx.string_findings.get("registry_key", [])]),

    IOCExtractor("oauth_endpoints", "OAuth / SSO Endpoints", "warn",
                 lambda ctx: [i["value"] for i in
                              ctx.string_findings.get("ms_oauth", [])
                              + ctx.string_findings.get("oauth_endpoint", [])]),

    IOCExtractor("uuids", "UUIDs / GUIDs", "info",
                 lambda ctx: [i["value"] for i in ctx.string_findings.get("uuid", [])]),

    IOCExtractor("env_vars", "Environment Variables", "info",
                 lambda ctx: [i["value"] for i in ctx.string_findings.get("env_variable", [])]),

    IOCExtractor("ad_indicators", "Active Directory Attack Indicators", "danger",
                 lambda ctx: [i["value"] for i in
                              ctx.string_findings.get("gmsa_attack", [])
                              + ctx.string_findings.get("kds_rootkey", [])
                              + ctx.string_findings.get("kerberos_attack", [])
                              + ctx.string_findings.get("dcsync_indicator", [])
                              + ctx.string_findings.get("mimikatz_command", [])]),

    IOCExtractor("ad_attributes", "AD Attributes / Privileged Groups", "warn",
                 lambda ctx: [i["value"] for i in
                              ctx.string_findings.get("ad_attribute", [])
                              + ctx.string_findings.get("ad_privileged_group", [])
                              + ctx.string_findings.get("gmsa_attribute", [])]),

    IOCExtractor("ldap_indicators", "LDAP Connection / Query Strings", "warn",
                 lambda ctx: [i["value"] for i in
                              ctx.string_findings.get("ldap_query", [])
                              + ctx.string_findings.get("ldap_connection", [])]),
]

try:
    from binanalysis.generated_ioc import GENERATED_IOC_EXTRACTORS
    IOC_EXTRACTORS = IOC_EXTRACTORS + GENERATED_IOC_EXTRACTORS
except ImportError:
    pass
