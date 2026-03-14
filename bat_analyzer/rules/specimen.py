"""Specimen-specific rules — detect specific malware families or campaigns.

These are clearly separated from generic rules so analysts know when a finding
is family-specific vs. technique-generic. Add new families as needed."""

from bat_analyzer.rules import Rule

SPECIMEN_RULES: list[Rule] = [
    # ── GitHub dead-drop C2 ──
    Rule("github_dead_drop", "exfiltration", "critical",
         "Exfiltrates data to GitHub repo (dead-drop C2) — contains PAT + API references",
         lambda ctx: ctx.has_finding("github_pat") and ctx.has_finding("github_api")),

    # ── OAuth / SSO token theft ──
    Rule("ms_oauth_theft", "credential_theft", "high",
         "Targets Microsoft OAuth / SSO tokens",
         lambda ctx: ctx.has_finding("ms_oauth") or ctx.has_finding("oauth_endpoint")),

    Rule("sso_nonce_extraction", "credential_theft", "high",
         "Extracts SSO nonce values for session hijacking",
         lambda ctx: ctx.has_finding("sso_nonce")),

    # ── Browser cookie theft via COM ──
    Rule("cookie_theft_com", "credential_theft", "high",
         "Steals browser cookies via COM interface (GetCookieInfoForUri)",
         lambda ctx: ctx.has_string_containing("GetCookieInfoForUri")),

    # ── Application masquerading ──
    Rule("masquerade_excel", "masquerading", "high",
         "Disguised as Microsoft Excel",
         lambda ctx: any("Excel" in ctx.version_info.get(k, "")
                         for k in ["ProductName", "FileDescription", "OriginalFilename"])),

    Rule("masquerade_word", "masquerading", "high",
         "Disguised as Microsoft Word",
         lambda ctx: any("Word" in ctx.version_info.get(k, "")
                         for k in ["ProductName", "FileDescription", "OriginalFilename"])),

    Rule("masquerade_chrome", "masquerading", "high",
         "Disguised as Google Chrome",
         lambda ctx: any("Chrome" in ctx.version_info.get(k, "")
                         for k in ["ProductName", "FileDescription", "OriginalFilename"])
                     and not ctx.has_string_containing("chrome.dll")),
]
