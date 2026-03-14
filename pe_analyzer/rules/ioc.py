"""IOC extractors — each pulls one category of indicators from the analysis context."""

from pe_analyzer.rules import IOCExtractor

IOC_EXTRACTORS: list[IOCExtractor] = [
    IOCExtractor("urls", "URLs", "warn",
                 lambda ctx: [i["value"] for i in ctx.string_findings.get("url", [])]),

    IOCExtractor("domains", "Domains", "info",
                 lambda ctx: [i["value"] for i in ctx.string_findings.get("domain", [])]),

    IOCExtractor("credentials", "Embedded Credentials / Tokens", "danger",
                 lambda ctx: [i["value"][:60] + "…" for i in
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
]
