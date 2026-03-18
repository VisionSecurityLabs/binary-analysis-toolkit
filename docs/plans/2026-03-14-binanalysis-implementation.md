# binanalysis Refactor Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Restructure pe_analyzer into a generic static binary analysis framework (`binanalysis`) with PE as the first format backend, so adding ELF/Mach-O later requires zero changes to existing code.

**Architecture:** Format-agnostic core (strings, hashes, entropy, IOCs, rule engine) + pluggable format backends registered via a `FormatHandler` dataclass. Each format provides a `Context` subclass and its own rules. Auto-detection routes to the right backend based on magic bytes.

**Tech Stack:** Python 3.10+, pefile (PE backend), yara-python + flare-capa (optional integrations)

---

### Task 1: Create binanalysis package skeleton

**Files:**
- Create: `binanalysis/__init__.py`
- Create: `binanalysis/generic/__init__.py`
- Create: `binanalysis/formats/__init__.py`
- Create: `binanalysis/formats/pe/__init__.py`
- Create: `binanalysis/formats/pe/rules/__init__.py`
- Create: `binanalysis/integrations/__init__.py`

**Step 1: Create directory structure**

```bash
mkdir -p binanalysis/generic binanalysis/formats/pe/rules binanalysis/integrations
```

**Step 2: Create all `__init__.py` files**

`binanalysis/__init__.py`:
```python
"""binanalysis — generic static binary analysis framework."""
```

`binanalysis/generic/__init__.py`:
```python
"""Format-agnostic analysis modules."""
```

`binanalysis/formats/__init__.py`:
```python
"""Format detection and registry."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from binanalysis.context import AnalysisContext

@dataclass
class FormatHandler:
    """A pluggable binary format backend."""
    name: str
    magic_check: Callable[[bytes], bool]
    analyze: Callable[[Path, bytes, dict], "AnalysisContext"]
    get_rules: Callable[[], list]

FORMATS: list[FormatHandler] = []

def register_format(handler: FormatHandler):
    """Register a format handler."""
    FORMATS.append(handler)

def detect_format(data: bytes) -> FormatHandler | None:
    """Auto-detect binary format from magic bytes."""
    return next((f for f in FORMATS if f.magic_check(data)), None)
```

`binanalysis/formats/pe/__init__.py`:
```python
"""PE format backend."""
```

`binanalysis/formats/pe/rules/__init__.py`:
```python
"""PE-specific behavioral rules."""
```

`binanalysis/integrations/__init__.py`:
```python
"""External tool integrations."""
```

**Step 3: Verify structure**

Run: `find binanalysis -type f | sort`

Expected:
```
binanalysis/__init__.py
binanalysis/formats/__init__.py
binanalysis/formats/pe/__init__.py
binanalysis/formats/pe/rules/__init__.py
binanalysis/generic/__init__.py
binanalysis/integrations/__init__.py
```

**Step 4: Commit**

```bash
git add binanalysis/
git commit -m "scaffold: create binanalysis package skeleton with format registry"
```

---

### Task 2: Move format-agnostic modules (output, strings, config)

**Files:**
- Copy: `pe_analyzer/output.py` → `binanalysis/output.py` (no changes)
- Copy: `pe_analyzer/strings.py` → `binanalysis/strings.py` (no changes)
- Create: `binanalysis/config.py` (copy SUSPICIOUS_STRING_PATTERNS only from pe_analyzer/config.py)

**Step 1: Copy output.py as-is**

Copy `pe_analyzer/output.py` to `binanalysis/output.py` — no changes needed, it's format-agnostic.

**Step 2: Copy strings.py as-is**

Copy `pe_analyzer/strings.py` to `binanalysis/strings.py` — no changes needed, works on raw bytes.

**Step 3: Create binanalysis/config.py**

Take only `SUSPICIOUS_STRING_PATTERNS` from `pe_analyzer/config.py`. The `SUSPICIOUS_IMPORTS` dict stays in the PE format module.

```python
"""Static configuration — format-agnostic string patterns."""

SUSPICIOUS_STRING_PATTERNS = [
    # URLs and domains
    (r'https?://[^\x00\s]{5,200}', "url"),
    (r'[a-zA-Z0-9-]+\.(com|net|org|io|xyz|top|ru|cn|tk|onion)', "domain"),
    # Credentials and tokens
    (r'github_pat_[A-Za-z0-9_]{30,}', "github_pat"),
    (r'ghp_[A-Za-z0-9]{36}', "github_token"),
    (r'Bearer\s+[A-Za-z0-9._\-]+', "bearer_token"),
    (r'Authorization:\s*.+', "auth_header"),
    (r'[A-Za-z0-9+/]{40,}={0,2}', "possible_base64"),
    # API and C2
    (r'api\.github\.com', "github_api"),
    (r'/repos/[^\x00\s]+', "github_repo_path"),
    (r'/contents/[^\x00\s]+', "github_contents_path"),
    (r'User-Agent:\s*.+', "user_agent"),
    (r'Content-Type:\s*.+', "content_type_header"),
    (r'Accept:\s*.+', "accept_header"),
    # OAuth / SSO
    (r'login\.microsoftonline\.com', "ms_oauth"),
    (r'oauth2?/authorize', "oauth_endpoint"),
    (r'sso_nonce', "sso_nonce"),
    (r'client_id=[^\x00\s&]+', "client_id"),
    (r'redirect_uri=[^\x00\s&]+', "redirect_uri"),
    (r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', "uuid"),
    # File system
    (r'C:\\[^\x00]{5,}', "windows_path"),
    (r'%[A-Z]+%', "env_variable"),
    (r'HKLM|HKCU|HKEY_', "registry_key"),
    # JSON structures
    (r'\{"[a-z_]+":', "json_object"),
    (r'"message":', "json_message_key"),
    (r'"content":', "json_content_key"),
    (r'"branch":', "json_branch_key"),
    # Recon
    (r'whoami|systeminfo|ipconfig|hostname|tasklist|wmic', "recon_command"),
]
```

**Step 4: Verify imports work**

Run: `cd /Users/Gil/Downloads/process && python -c "from binanalysis.output import heading; from binanalysis.strings import extract_ascii_strings; from binanalysis.config import SUSPICIOUS_STRING_PATTERNS; print('OK')"`

Expected: `OK`

**Step 5: Commit**

```bash
git add binanalysis/output.py binanalysis/strings.py binanalysis/config.py
git commit -m "feat: add format-agnostic output, strings, and config modules"
```

---

### Task 3: Create base AnalysisContext

**Files:**
- Create: `binanalysis/context.py`

**Step 1: Write the base context**

```python
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

    def any_section(self, predicate) -> bool:
        return any(predicate(s) for s in self.sections)
```

**Step 2: Verify import**

Run: `python -c "from binanalysis.context import AnalysisContext; print('OK')"`

Expected: `OK`

**Step 3: Commit**

```bash
git add binanalysis/context.py
git commit -m "feat: add base AnalysisContext with format-agnostic predicates"
```

---

### Task 4: Create generic analysis modules (hashes, strings analysis)

**Files:**
- Create: `binanalysis/generic/hashes.py` (extracted from pe_analysis.py:analyze_hashes)
- Create: `binanalysis/generic/strings.py` (extracted from pe_analysis.py:analyze_strings + analyze_dynamic_apis)

**Step 1: Create binanalysis/generic/hashes.py**

```python
"""File hash computation — format-agnostic."""

import hashlib
from pathlib import Path

from binanalysis.output import heading, detail


def analyze_hashes(filepath: Path, data: bytes) -> dict:
    heading("FILE HASHES")
    hashes = {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    detail("MD5", hashes["md5"])
    detail("SHA1", hashes["sha1"])
    detail("SHA256", hashes["sha256"])
    detail("File Size", f"{len(data)} bytes ({len(data)/1024:.1f} KB)")
    detail("File Name", filepath.name)
    return hashes
```

**Step 2: Create binanalysis/generic/strings.py**

This extracts both `analyze_strings` and `analyze_dynamic_apis` from `pe_analysis.py`. These work on raw bytes, not PE structures.

```python
"""String analysis — pattern matching and dynamic API detection on raw bytes."""

import re

from binanalysis.config import SUSPICIOUS_STRING_PATTERNS
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
```

**Step 3: Verify imports**

Run: `python -c "from binanalysis.generic.hashes import analyze_hashes; from binanalysis.generic.strings import analyze_strings, analyze_dynamic_apis; print('OK')"`

Expected: `OK`

**Step 4: Commit**

```bash
git add binanalysis/generic/
git commit -m "feat: add generic hashes and string analysis modules"
```

---

### Task 5: Create rule engine (format-agnostic)

**Files:**
- Create: `binanalysis/rules.py` (dataclasses + runners from pe_analyzer/rules/__init__.py)
- Create: `binanalysis/ioc.py` (IOC extractors from pe_analyzer/rules/ioc.py)
- Create: `binanalysis/generic/rules.py` (entropy/string-only rules extracted from pe_analyzer/rules/generic.py)

**Step 1: Create binanalysis/rules.py**

The rule engine framework. `Rule` and `IOCExtractor` dataclasses plus runners. The runner now accepts a `generic_rules` and `format_rules` split.

```python
"""Rule engine — dataclasses and runner for behavioral rules and IOC extractors."""

import logging
from dataclasses import dataclass
from typing import Callable

from binanalysis.context import AnalysisContext
from binanalysis.output import heading, subheading, info, warn, danger, detail

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
                         generic_rules: list[Rule] | None = None,
                         format_rules: list[Rule] | None = None) -> list[dict]:
    """Evaluate generic + format-specific rules against the context."""
    from binanalysis.generic.rules import GENERIC_RULES

    heading("BEHAVIORAL ANALYSIS")

    if generic_rules is None:
        generic_rules = GENERIC_RULES
    if format_rules is None:
        format_rules = []

    all_rules = generic_rules + format_rules

    triggered = []
    for rule in all_rules:
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
    from binanalysis.ioc import IOC_EXTRACTORS

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

    return iocs
```

**Step 2: Create binanalysis/ioc.py**

```python
"""IOC extractors — each pulls one category of indicators from the analysis context."""

from binanalysis.rules import IOCExtractor

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
```

**Step 3: Create binanalysis/generic/rules.py**

Extract only the rules from `pe_analyzer/rules/generic.py` that do NOT use `has_import` / `has_all_imports` — those are PE-specific. Only entropy and string-based rules are truly generic.

```python
"""Generic behavioral rules — format-agnostic, work on any binary.
Only entropy-based and string-based checks belong here."""

from binanalysis.rules import Rule

GENERIC_RULES: list[Rule] = [
    Rule("rwx_section", "evasion", "high",
         "Section with both WRITE and EXECUTE permissions",
         lambda ctx: ctx.any_section(
             lambda s: "EXEC" in s.get("characteristics", "") and "WRITE" in s.get("characteristics", ""))),

    Rule("high_entropy_section", "evasion", "medium",
         "Section with entropy > 7.0 (likely packed or encrypted)",
         lambda ctx: ctx.any_section(lambda s: s.get("entropy", 0) > 7.0)),

    Rule("embedded_urls", "network", "medium",
         "Contains embedded URLs",
         lambda ctx: ctx.has_finding("url")),

    Rule("recon_commands", "discovery", "medium",
         "Contains reconnaissance commands (whoami, systeminfo, etc.)",
         lambda ctx: ctx.has_finding("recon_command")),

    Rule("anti_vm", "evasion", "medium",
         "Virtual machine / sandbox detection strings",
         lambda ctx: any(ctx.has_string_containing(vm) for vm in [
             "VMwareService", "VMwareTray", "VBoxService", "VBoxTray",
             "qemu-ga", "QEMU", "Sandboxie", "SbieDll", "cuckoomon",
             "wine_get_unix_file_name",
         ])),
]
```

**Step 4: Verify**

Run: `python -c "from binanalysis.rules import Rule, run_behavioral_rules; from binanalysis.ioc import IOC_EXTRACTORS; from binanalysis.generic.rules import GENERIC_RULES; print(f'{len(GENERIC_RULES)} generic rules, {len(IOC_EXTRACTORS)} extractors')"`

Expected: `5 generic rules, 9 extractors`

**Step 5: Commit**

```bash
git add binanalysis/rules.py binanalysis/ioc.py binanalysis/generic/rules.py
git commit -m "feat: add format-agnostic rule engine, IOC extractors, and generic rules"
```

---

### Task 6: Create PE format backend — context and config

**Files:**
- Create: `binanalysis/formats/pe/context.py`
- Create: `binanalysis/formats/pe/config.py` (SUSPICIOUS_IMPORTS from pe_analyzer/config.py)

**Step 1: Create PE context subclass**

`binanalysis/formats/pe/context.py`:
```python
"""PEContext — PE-specific analysis context."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from binanalysis.context import AnalysisContext

if TYPE_CHECKING:
    import pefile


@dataclass
class PEContext(AnalysisContext):
    """PE-specific context with imports, version info, and pefile object."""
    pe: pefile.PE = None
    imports: dict = None                # dll_name -> [func_names]
    flat_imports: set = None            # all import function names
    version_info: dict = None
    dynamic_apis: list = None
    exports: list = None

    # ── PE-specific predicates ──

    def has_import(self, *names: str) -> bool:
        return bool(self.flat_imports & set(names))

    def has_all_imports(self, *names: str) -> bool:
        return set(names) <= self.flat_imports
```

**Step 2: Create PE config**

`binanalysis/formats/pe/config.py`:
```python
"""PE-specific configuration — suspicious Windows API imports."""

SUSPICIOUS_IMPORTS = {
    "injection": [
        "VirtualAllocEx", "WriteProcessMemory", "ReadProcessMemory",
        "CreateRemoteThread", "NtCreateThreadEx", "RtlCreateUserThread",
        "OpenProcess", "NtOpenProcess", "QueueUserAPC",
        "SetWindowsHookEx", "SetWindowsHookExA", "SetWindowsHookExW",
    ],
    "process": [
        "CreateProcessW", "CreateProcessA", "WinExec", "ShellExecuteW",
        "ShellExecuteA", "ShellExecuteExW",
    ],
    "persistence": [
        "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA",
        "RegCreateKeyExW", "CreateServiceW", "CreateServiceA",
    ],
    "credential_theft": [
        "CredEnumerateA", "CredEnumerateW", "CryptUnprotectData",
        "LsaEnumerateLogonSessions", "SamEnumerateUsersInDomain",
    ],
    "network": [
        "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest",
        "WinHttpSendRequest", "WinHttpReceiveResponse", "WinHttpReadData",
        "InternetOpenA", "InternetOpenW", "InternetConnectA",
        "InternetConnectW", "HttpOpenRequestA", "HttpSendRequestA",
        "URLDownloadToFileA", "URLDownloadToFileW",
        "WSAStartup", "connect", "send", "recv",
    ],
    "crypto": [
        "CryptEncrypt", "CryptDecrypt", "CryptAcquireContextA",
        "CryptBinaryToStringA", "CryptStringToBinaryA",
        "BCryptEncrypt", "BCryptDecrypt", "BCryptGenRandom",
    ],
    "evasion": [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
        "NtQueryInformationProcess", "GetTickCount", "QueryPerformanceCounter",
        "VirtualProtect", "VirtualQuery",
    ],
    "token_manipulation": [
        "OpenProcessToken", "AdjustTokenPrivileges",
        "LookupPrivilegeValueA", "ImpersonateLoggedOnUser",
        "DuplicateTokenEx",
    ],
    "com": [
        "CoCreateInstance", "CoInitializeEx", "CoCreateGuid",
    ],
}
```

**Step 3: Verify**

Run: `python -c "from binanalysis.formats.pe.context import PEContext; from binanalysis.formats.pe.config import SUSPICIOUS_IMPORTS; print(f'{len(SUSPICIOUS_IMPORTS)} categories')"`

Expected: `8 categories`

**Step 4: Commit**

```bash
git add binanalysis/formats/pe/
git commit -m "feat: add PEContext subclass and PE-specific suspicious imports config"
```

---

### Task 7: Create PE format backend — analysis functions

**Files:**
- Create: `binanalysis/formats/pe/analysis.py` (PE-specific analysis functions from pe_analysis.py)

**Step 1: Create PE analysis module**

Copy all PE-specific functions from `pe_analyzer/pe_analysis.py` into `binanalysis/formats/pe/analysis.py`, updating imports to use `binanalysis.*`. Remove `analyze_hashes`, `analyze_strings`, and `analyze_dynamic_apis` (they moved to generic).

The functions to include:
- `analyze_pe_headers(pe)` — unchanged logic
- `analyze_sections(pe)` — unchanged logic
- `analyze_imports(pe)` — update to use `binanalysis.formats.pe.config.SUSPICIOUS_IMPORTS`
- `analyze_exports(pe)` — unchanged logic
- `analyze_resources(pe)` — unchanged logic
- `analyze_version_info(pe)` — unchanged logic
- `analyze_tls(pe)` — unchanged logic
- `analyze_compiler(data, pe, ...)` — unchanged logic

Update all imports from:
```python
from pe_analyzer.config import SUSPICIOUS_IMPORTS, SUSPICIOUS_STRING_PATTERNS
from pe_analyzer.output import C, heading, subheading, info, warn, danger, detail
from pe_analyzer.strings import extract_ascii_strings, extract_wide_strings
```
To:
```python
from binanalysis.formats.pe.config import SUSPICIOUS_IMPORTS
from binanalysis.output import C, heading, subheading, info, warn, danger, detail
from binanalysis.strings import extract_ascii_strings, extract_wide_strings
```

**Step 2: Verify**

Run: `python -c "from binanalysis.formats.pe.analysis import analyze_pe_headers, analyze_sections, analyze_imports; print('OK')"`

Expected: `OK`

**Step 3: Commit**

```bash
git add binanalysis/formats/pe/analysis.py
git commit -m "feat: add PE-specific analysis functions (headers, imports, sections, etc.)"
```

---

### Task 8: Create PE format backend — rules

**Files:**
- Create: `binanalysis/formats/pe/rules/generic.py` (import-based rules from pe_analyzer/rules/generic.py)
- Create: `binanalysis/formats/pe/rules/specimen.py` (from pe_analyzer/rules/specimen.py)

**Step 1: Create PE generic rules**

Copy all rules from `pe_analyzer/rules/generic.py` that use `has_import` or `has_all_imports`. Remove the ones that moved to `binanalysis/generic/rules.py` (rwx_section, high_entropy_section, embedded_urls, recon_commands, anti_vm).

Update imports:
```python
from binanalysis.formats.pe.context import PEContext
from binanalysis.rules import Rule
```

The `_check_version_mismatch` helper and remaining ~23 import-based rules stay here.

**Step 2: Create PE specimen rules**

Copy `pe_analyzer/rules/specimen.py` with updated imports:
```python
from binanalysis.rules import Rule
```

Rules reference `ctx.has_finding()`, `ctx.has_string_containing()`, and `ctx.version_info` — all available on PEContext.

**Step 3: Update `binanalysis/formats/pe/rules/__init__.py`**

```python
"""PE-specific behavioral rules."""

from binanalysis.formats.pe.rules.generic import PE_GENERIC_RULES
from binanalysis.formats.pe.rules.specimen import SPECIMEN_RULES

PE_RULES = PE_GENERIC_RULES + SPECIMEN_RULES
```

**Step 4: Verify**

Run: `python -c "from binanalysis.formats.pe.rules import PE_RULES; print(f'{len(PE_RULES)} PE rules')"`

Expected: `30 PE rules` (23 import-based generic + 7 specimen)

**Step 5: Commit**

```bash
git add binanalysis/formats/pe/rules/
git commit -m "feat: add PE-specific behavioral and specimen rules"
```

---

### Task 9: Register PE format handler and build analyze entry point

**Files:**
- Modify: `binanalysis/formats/pe/__init__.py`
- Create: `binanalysis/integrations/capa_runner.py` (copy from pe_analyzer, update imports)
- Create: `binanalysis/integrations/yara_runner.py` (copy from pe_analyzer, update imports)

**Step 1: Create PE format handler**

`binanalysis/formats/pe/__init__.py`:
```python
"""PE format backend — registration and main analyze function."""

from pathlib import Path

import pefile

from binanalysis.formats import FormatHandler, register_format
from binanalysis.formats.pe.context import PEContext
from binanalysis.formats.pe.analysis import (
    analyze_pe_headers, analyze_sections, analyze_imports,
    analyze_exports, analyze_resources, analyze_version_info,
    analyze_tls, analyze_compiler,
)
from binanalysis.formats.pe.rules import PE_RULES
from binanalysis.strings import extract_ascii_strings, extract_wide_strings
from binanalysis.output import heading, detail


def analyze_pe(filepath: Path, data: bytes, generic_results: dict) -> PEContext:
    """Run all PE-specific analyses and return a PEContext."""
    pe = pefile.PE(data=data)

    ascii_set = generic_results["ascii_set"]
    wide_set = generic_results["wide_set"]

    results = generic_results.setdefault("format_specific", {})
    results["pe_headers"] = analyze_pe_headers(pe)
    results["sections"] = analyze_sections(pe)
    results["imports"] = analyze_imports(pe)
    results["exports"] = analyze_exports(pe)
    results["resources"] = analyze_resources(pe)
    results["version_info"] = analyze_version_info(pe)
    results["tls"] = analyze_tls(pe)
    results["compiler"] = analyze_compiler(data, pe, ascii_strs=ascii_set, wide_strs=wide_set)

    # Build flat imports set
    flat = set()
    for funcs in results["imports"].values():
        flat.update(funcs)

    return PEContext(
        filepath=filepath,
        data=data,
        format_name="PE",
        ascii_strings=ascii_set,
        wide_strings=wide_set,
        all_strings=ascii_set | wide_set,
        string_findings=generic_results["strings"],
        sections=results["sections"],
        hashes=generic_results["hashes"],
        pe=pe,
        imports=results["imports"],
        flat_imports=flat,
        version_info=results["version_info"],
        dynamic_apis=generic_results.get("dynamic_apis", []),
        exports=results["exports"],
    )


def get_pe_rules():
    return PE_RULES


register_format(FormatHandler(
    name="PE",
    magic_check=lambda data: data[:2] == b'MZ',
    analyze=analyze_pe,
    get_rules=get_pe_rules,
))
```

**Step 2: Copy integrations with updated imports**

Copy `pe_analyzer/integrations/capa_runner.py` → `binanalysis/integrations/capa_runner.py`, changing:
```python
from pe_analyzer.output import ...
```
to:
```python
from binanalysis.output import ...
```

Same for `yara_runner.py`.

**Step 3: Verify**

Run: `python -c "from binanalysis.formats.pe import analyze_pe; print('OK')"`

Expected: `OK`

**Step 4: Commit**

```bash
git add binanalysis/formats/pe/__init__.py binanalysis/integrations/
git commit -m "feat: register PE format handler and add integrations"
```

---

### Task 10: Create CLI entry point (__main__.py)

**Files:**
- Create: `binanalysis/__main__.py`

**Step 1: Write the CLI**

```python
"""CLI entry point — python -m binanalysis <file> [--json]"""

import sys
import json
from pathlib import Path

from binanalysis.output import C, heading, subheading, info, warn, danger, detail
from binanalysis.strings import extract_ascii_strings, extract_wide_strings
from binanalysis.generic.hashes import analyze_hashes
from binanalysis.generic.strings import analyze_strings, analyze_dynamic_apis
from binanalysis.rules import run_behavioral_rules, run_ioc_extractors
from binanalysis.formats import detect_format

# Import format backends to trigger registration
import binanalysis.formats.pe  # noqa: F401

from binanalysis.integrations.capa_runner import run_capa_analysis
from binanalysis.integrations.yara_runner import run_yara_scan


def classify(behaviors: list[dict], capa_results: list[dict], yara_results: list[dict]):
    """Print final verdict combining custom rules, capa capabilities, and YARA matches."""
    heading("CLASSIFICATION")

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for b in behaviors:
        counts[b.get("severity", "low")] += 1

    offensive_namespaces = {
        "anti-analysis", "collection", "impact", "persistence",
        "exploitation", "communication",
    }
    capa_offensive = [c for c in capa_results
                      if c.get("namespace", "").split("/")[0] in offensive_namespaces
                      or c.get("att&ck")]
    if len(capa_offensive) >= 5:
        counts["high"] += 1
    elif len(capa_offensive) >= 3:
        counts["medium"] += 1

    yara_suspicious = [y for y in yara_results
                       if y["source"] in ("antidebug_antivm.yar", "packer.yar")]
    if yara_suspicious:
        counts["medium"] += 1

    if counts["critical"] > 0:
        danger("VERDICT: MALICIOUS — Critical indicators detected")
    elif counts["high"] >= 2:
        danger("VERDICT: LIKELY MALICIOUS — Multiple high-severity indicators")
    elif counts["high"] >= 1:
        warn("VERDICT: SUSPICIOUS — High-severity indicators present")
    elif counts["medium"] >= 2:
        warn("VERDICT: SUSPICIOUS — Multiple medium-severity indicators")
    else:
        info("VERDICT: No strong malicious indicators (may require dynamic analysis)")

    if behaviors:
        subheading("Custom Rules")
        for b in behaviors:
            color = C.RED if b["severity"] in ("critical", "high") else C.YELLOW
            print(f"      {color}[{b['severity'].upper()}]{C.RESET} {b['description']}")

    if capa_offensive:
        subheading(f"Capa Offensive Capabilities ({len(capa_offensive)}/{len(capa_results)} total)")
        for c in capa_offensive[:10]:
            att = f"  [{c['att&ck'][0]}]" if c.get("att&ck") else ""
            print(f"      {C.YELLOW}[CAPA]{C.RESET} {c['name']}{att}")

    if yara_suspicious:
        subheading("YARA Suspicious Signatures")
        for y in yara_suspicious:
            print(f"      {C.YELLOW}[YARA]{C.RESET} {y['rule']}  ({y['source']})")


def generate_report(filepath: Path, all_results: dict):
    report_path = filepath.parent / f"{filepath.stem}_analysis.json"
    with open(report_path, "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    heading("REPORT SAVED")
    info(f"JSON report: {report_path}")


def main():
    if len(sys.argv) < 2:
        print(f"Usage: python -m binanalysis <binary_file> [--json]")
        sys.exit(1)

    filepath = Path(sys.argv[1])
    save_json = "--json" in sys.argv

    if not filepath.exists():
        print(f"[!] File not found: {filepath}")
        sys.exit(1)

    with open(filepath, "rb") as f:
        data = f.read()

    handler = detect_format(data)
    if handler is None:
        print("[!] Unsupported binary format (not PE, ELF, or Mach-O)")
        sys.exit(1)

    print(f"{C.BOLD}{C.MAGENTA}")
    print("╔══════════════════════════════════════════════════════════════════════╗")
    print("║                   STATIC BINARY ANALYZER                           ║")
    print("╚══════════════════════════════════════════════════════════════════════╝")
    print(C.RESET)

    # Pre-extract strings
    ascii_raw = extract_ascii_strings(data, min_len=4)
    wide_raw = extract_wide_strings(data, min_len=4)
    ascii_set = {s for _, s in ascii_raw}
    wide_set = {s for _, s in wide_raw}

    # Generic analysis
    generic_results = {
        "ascii_set": ascii_set,
        "wide_set": wide_set,
    }
    generic_results["hashes"] = analyze_hashes(filepath, data)
    generic_results["strings"] = analyze_strings(data, ascii_strings=ascii_raw, wide_strings=wide_raw)
    generic_results["dynamic_apis"] = analyze_dynamic_apis(data)

    # Format-specific analysis
    ctx = handler.analyze(filepath, data, generic_results)

    info(f"Format: {handler.name}")
    if hasattr(ctx, 'pe'):
        machine = generic_results.get("format_specific", {}).get("pe_headers", {}).get("machine", "?")
        subsys = generic_results.get("format_specific", {}).get("pe_headers", {}).get("subsystem", "?")
        detail("Architecture", f"{machine}, {subsys}")

    # Behavioral rules: generic + format-specific
    format_rules = handler.get_rules()
    behaviors = run_behavioral_rules(ctx, format_rules=format_rules)

    # IOC extraction
    iocs = run_ioc_extractors(ctx)

    # Integrations
    capa_results = run_capa_analysis(filepath)
    yara_results = run_yara_scan(data)

    # Verdict
    classify(behaviors, capa_results, yara_results)

    if save_json:
        results = {
            "generic": {
                "hashes": generic_results["hashes"],
                "strings": {
                    k: [{"value": i["value"], "encoding": i["encoding"]} for i in v]
                    for k, v in generic_results["strings"].items()
                },
                "dynamic_apis": generic_results["dynamic_apis"],
            },
            "format_specific": generic_results.get("format_specific", {}),
            "behavior": {"behaviors": behaviors},
            "iocs": iocs,
            "capa": capa_results,
            "yara": yara_results,
        }
        generate_report(filepath, results)

    print()


if __name__ == "__main__":
    main()
```

**Step 2: Verify it loads**

Run: `python -c "from binanalysis.__main__ import main; print('OK')"`

Expected: `OK`

**Step 3: Test with existing PE sample**

Run: `python -m binanalysis /Users/Gil/Downloads/process/6543fd8ffdfaa79e5a625d59f80207d17099f779d7d3fd07b59c9dfe665e6c30 2>&1 | head -20`

Expected: Banner says "STATIC BINARY ANALYZER", format detected as PE, analysis runs.

**Step 4: Commit**

```bash
git add binanalysis/__main__.py
git commit -m "feat: add CLI entry point with auto-format detection"
```

---

### Task 11: Smoke test and final verification

**Step 1: Run full analysis on PE sample**

Run: `python -m binanalysis /Users/Gil/Downloads/process/6543fd8ffdfaa79e5a625d59f80207d17099f779d7d3fd07b59c9dfe665e6c30 --json`

Verify:
- Banner shows "STATIC BINARY ANALYZER"
- All sections appear (hashes, headers, sections, imports, etc.)
- Behavioral rules fire
- IOCs extracted
- JSON report written with `generic` and `format_specific` top-level keys

**Step 2: Compare output with old tool**

Run: `python -m pe_analyzer /Users/Gil/Downloads/process/6543fd8ffdfaa79e5a625d59f80207d17099f779d7d3fd07b59c9dfe665e6c30 2>&1 | wc -l` and compare line count with binanalysis output. They should be similar.

**Step 3: Verify unsupported format is handled**

Run: `echo "not a binary" > /tmp/test.txt && python -m binanalysis /tmp/test.txt`

Expected: `[!] Unsupported binary format (not PE, ELF, or Mach-O)`

**Step 4: Final commit**

```bash
git add -A
git commit -m "feat: binanalysis v1.0 — generic static binary analysis framework with PE backend"
```
