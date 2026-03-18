"""String analysis — pattern matching and dynamic API detection on raw bytes."""

import re

from binanalysis.config import SUSPICIOUS_STRING_PATTERNS
from binanalysis.generic.deobfuscate import deobfuscate_strings
from binanalysis.output import heading, subheading, info, warn, danger
from binanalysis.strings import extract_ascii_strings, extract_wide_strings

CATEGORY_LABELS = {
    "url": "URLs",
    "domain": "Domains / Hostnames",
    "github_pat": "GitHub Personal Access Tokens",
    "github_token": "GitHub Tokens",
    "bearer_token": "Bearer Tokens",
    "auth_header": "Authorization Headers",
    "github_api": "GitHub API References",
    "github_repo_path": "GitHub Repo Paths",
    "github_contents_path": "GitHub Contents Paths",
    "user_agent": "User-Agent Strings",
    "content_type_header": "Content-Type Headers",
    "accept_header": "Accept Headers",
    "ms_oauth": "Microsoft OAuth Endpoints",
    "oauth_endpoint": "OAuth Endpoints",
    "sso_nonce": "SSO Nonce References",
    "client_id": "Client IDs",
    "redirect_uri": "Redirect URIs",
    "uuid": "UUIDs / GUIDs",
    "windows_path": "Windows File Paths",
    "env_variable": "Environment Variables",
    "registry_key": "Registry Keys",
    "json_object": "JSON Structures",
    "json_message_key": "JSON 'message' Keys",
    "json_content_key": "JSON 'content' Keys",
    "json_branch_key": "JSON 'branch' Keys",
    "recon_command": "Reconnaissance Commands",
    "possible_base64": "Possible Base64 Blobs",
}

SKIP_DISPLAY = {"possible_base64"}


def analyze_strings(data: bytes,
                    ascii_strings: list[tuple[int, str]] | None = None,
                    wide_strings: list[tuple[int, str]] | None = None) -> dict:
    heading("STRING ANALYSIS")

    if ascii_strings is None:
        ascii_strings = extract_ascii_strings(data, min_len=4)
    if wide_strings is None:
        wide_strings = extract_wide_strings(data, min_len=4)

    all_strings = [(off, s, "ascii") for off, s in ascii_strings]
    all_strings += [(off, s, "wide") for off, s in wide_strings]

    # Deobfuscate — decode base64/hex/XOR blobs and re-run pattern matching on results
    deob = deobfuscate_strings(ascii_strings or []) + deobfuscate_strings(wide_strings or [])
    all_strings += [(off, s, "deobfuscated") for off, s in deob]

    findings = {}

    for offset, string, encoding in all_strings:
        for pattern, category in SUSPICIOUS_STRING_PATTERNS:
            for m in re.finditer(pattern, string, re.IGNORECASE):
                match_str = m.group()
                findings.setdefault(category, []).append({
                    "value": match_str,
                    "offset": offset,
                    "encoding": encoding,
                    "full_string": string[:200],
                })

    # Deduplicate by value within each category
    for cat in findings:
        seen = set()
        deduped = []
        for item in findings[cat]:
            if item["value"] not in seen:
                seen.add(item["value"])
                deduped.append(item)
        findings[cat] = deduped

    for cat, items in sorted(findings.items()):
        if cat in SKIP_DISPLAY:
            continue
        label = CATEGORY_LABELS.get(cat, cat)
        subheading(label)
        for item in items[:20]:
            enc_tag = f" [{item['encoding']}]" if item['encoding'] == 'wide' else ""
            if cat in ("github_pat", "github_token", "bearer_token"):
                danger(f"{item['value']}{enc_tag}")
            elif cat in ("url", "ms_oauth", "github_api", "windows_path"):
                warn(f"{item['value']}{enc_tag}")
            else:
                info(f"{item['value']}{enc_tag}")

    return findings


def analyze_dynamic_apis(data: bytes) -> list[str]:
    heading("DYNAMICALLY RESOLVED APIs")

    suspicious_keywords = [
        "Create", "Open", "Write", "Read", "Virtual", "Alloc", "Process",
        "Thread", "Token", "Registry", "Shell", "Internet", "Http", "Socket",
        "Inject", "Hook", "Crypt", "Download", "Upload", "Execute", "Startup",
        "Service", "Pipe", "LoadLibrary", "GetProc",
    ]

    api_names = set()
    for m in re.finditer(rb'([A-Z][a-zA-Z0-9]{5,50}(?:W|A)?)\x00', data):
        name = m.group(1).decode('ascii', errors='ignore')
        if any(kw in name for kw in suspicious_keywords):
            api_names.add(name)

    if api_names:
        for name in sorted(api_names):
            warn(f"{name}")
    else:
        info("No dynamically resolved suspicious APIs detected")

    return sorted(api_names)
