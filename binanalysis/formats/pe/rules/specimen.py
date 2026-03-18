"""Specimen-specific rules — detect specific malware families or campaigns.

These are clearly separated from generic rules so analysts know when a finding
is family-specific vs. technique-generic. Add new families as needed."""

import pefile

from binanalysis.rules import Rule


def _has_suspicious_overlay(ctx) -> bool:
    """Check if PE has overlay data beyond the Authenticode signature.

    Signed binaries always have overlay (the signature lives there),
    so we subtract the security directory size to avoid false positives.
    Only flag when extra data remains after accounting for the signature.
    """
    if not (hasattr(ctx, 'pe') and ctx.pe is not None):
        return False
    if not (hasattr(ctx, 'exports') and len(ctx.exports) > 0):
        return False
    overlay_start = ctx.pe.get_overlay_data_start_offset()
    if overlay_start is None:
        return False
    overlay_size = len(ctx.data) - overlay_start
    if overlay_size <= 0:
        return False
    # Subtract Authenticode signature size if present
    security_dir = ctx.pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
    if security_dir.VirtualAddress and security_dir.Size:
        overlay_size -= security_dir.Size
    # Only flag if substantial non-signature overlay remains (> 512 bytes)
    return overlay_size > 512


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

    # ── GoldenGMSA — AD gMSA password attack tool (Semperis) ──
    Rule("goldengmsa_family", "offensive_tool", "critical",
         "GoldenGMSA tool — computes gMSA passwords from KDS root keys (T1555/T1003)",
         lambda ctx: (ctx.has_string_containing("GoldenGMSA")
                      or (ctx.has_string_containing("GmsaPassword")
                          and ctx.has_string_containing("KdsUtils")))),

    Rule("gmsa_password_extraction", "credential_theft", "critical",
         "Contains gMSA password extraction methods (GetPassword, ManagedPasswordId)",
         lambda ctx: (ctx.has_string_containing("GetPassword")
                      and ctx.has_string_containing("ManagedPasswordId"))),

    Rule("kds_rootkey_dump", "credential_theft", "high",
         "Dumps AD KDS root keys used to derive gMSA passwords",
         lambda ctx: (ctx.has_string_containing("GroupKeyEnvelope")
                      and (ctx.has_string_containing("KdsCreateTime")
                           or ctx.has_string_containing("GetAllRootKeys")))),

    Rule("ad_ldap_enumeration", "discovery", "high",
         "Performs LDAP queries against Active Directory (DirectoryServices + FindAll)",
         lambda ctx: (ctx.has_string_containing("DirectoryServices")
                      and ctx.has_string_containing("FindAll")
                      and ctx.has_string_containing("GetCurrentDomain"))),

    Rule("costura_fody_packing", "evasion", "medium",
         ".NET assemblies embedded via Costura/Fody — dependencies hidden inside resources",
         lambda ctx: (ctx.has_string_containing("Costura.AssemblyLoader")
                      or (ctx.has_string_containing("ProcessedByFody")
                          and ctx.has_string_containing("ReadFromEmbeddedResources")))),

    Rule("timestomped_future_compile", "evasion", "medium",
         "PE compile timestamp is set in the future — likely timestomped",
         lambda ctx: (hasattr(ctx, 'pe') and ctx.pe is not None
                      and ctx.pe.FILE_HEADER.TimeDateStamp > 2000000000)),

    # ── Generic AD attack tool detection ──
    Rule("dcsync_capability", "credential_theft", "critical",
         "Contains DCSync / AD replication primitives (DsGetNCChanges / DRSUAPI)",
         lambda ctx: ctx.has_finding("dcsync_indicator")),

    Rule("kerberos_attack_tool", "credential_theft", "critical",
         "Contains Kerberos attack strings (Kerberoast / AS-REP roast / ticket manipulation)",
         lambda ctx: ctx.has_finding("kerberos_attack")),

    Rule("mimikatz_indicators", "credential_theft", "critical",
         "Contains Mimikatz-style credential dumping commands",
         lambda ctx: ctx.has_finding("mimikatz_command")),

    Rule("ad_recon_tool", "discovery", "high",
         "Enumerates AD attributes (SPNs, privileged groups, account names)",
         lambda ctx: (ctx.has_finding("ad_attribute")
                      and ctx.has_finding("ldap_query"))),

    Rule("dotnet_single_import", "evasion", "low",
         ".NET binary with only mscoree.dll import — all real deps resolved at runtime",
         lambda ctx: (hasattr(ctx, 'imports') and len(ctx.imports) == 1
                      and "mscoree.dll" in ctx.imports)),

    # ── Suspicious DLL loader pattern ──
    Rule("dll_single_generic_export", "execution", "high",
         "DLL exports a single generic entry point (Script/Run/Execute/Main) — loader pattern",
         lambda ctx: (hasattr(ctx, 'exports') and len(ctx.exports) == 1
                      and ctx.exports[0] in ("Script", "Run", "Execute", "Main", "Start",
                                              "Entry", "Init", "Load", "DllMain"))),

    Rule("signed_no_version_info", "masquerading", "high",
         "Binary has code-signing cert URLs but no version info — stolen or misused signature",
         lambda ctx: (not ctx.version_info
                      and (ctx.has_string_containing("ocsp.globalsign")
                           or ctx.has_string_containing("ocsp.digicert")
                           or ctx.has_string_containing("ocsp.sectigo")
                           or ctx.has_string_containing("ocsp.comodoca")
                           or ctx.has_string_containing("ocsp.entrust")))),

    Rule("dll_with_overlay", "evasion", "medium",
         "DLL has non-signature overlay data — may contain embedded payload",
         lambda ctx: _has_suspicious_overlay(ctx)),

    Rule("tls_plus_antidebug_combo", "evasion", "high",
         "TLS callback combined with anti-debug — code runs before debugger can attach",
         lambda ctx: (hasattr(ctx, 'pe') and ctx.pe is not None
                      and hasattr(ctx.pe, "DIRECTORY_ENTRY_TLS") and bool(ctx.pe.DIRECTORY_ENTRY_TLS)
                      and ctx.has_import("IsDebuggerPresent"))),

    Rule("excessive_math_imports", "crypto", "medium",
         "Imports full math library (sin/cos/pow/sqrt) — potential custom crypto or obfuscation",
         lambda ctx: (hasattr(ctx, 'flat_imports')
                      and sum(1 for f in ("sin", "cos", "tan", "pow", "sqrt", "exp", "log", "acos", "asin", "atan")
                              if f in ctx.flat_imports) >= 6)),
]
