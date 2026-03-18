# Binary Analysis Toolkit (BAT)

A command-line tool for automated static analysis of binary files. It currently supports Windows PE (Portable Executable) binaries with architecture ready for ELF and Mach-O formats. The tool examines executables without running them, identifies malicious behavior patterns, extracts actionable indicators of compromise (IOCs), and classifies threats -- giving CERT and SOC analysts a fast, structured starting point for triage and investigation.

Written in Python. The base dependencies are `pefile` and `yara-python`; capa, decompilers, and other integrations are optional.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Why This Tool](#why-this-tool)
- [Features at a Glance](#features-at-a-glance)
- [Malware Family Coverage](#malware-family-coverage)
- [Installation](#installation)
- [Usage Examples](#usage-examples)
- [CLI Reference](#cli-reference)
- [Configuration File](#configuration-file)
- [Understanding the Output](#understanding-the-output)
- [JSON Report](#json-report)
- [Architecture](#architecture)
- [Contributing](#contributing)
- [License](#license)

---

## Quick Start

```bash
# Install
git clone <repo-url> && cd binary-analysis-toolkit
uv sync

# Analyze a binary (basic analysis only)
uv run binanalysis suspicious.exe

# With YARA community rules (auto-downloads on first use)
uv run binanalysis suspicious.exe --yara

# With capa capability detection (auto-downloads rules on first use)
uv run binanalysis suspicious.exe --capa

# With JSON report
uv run binanalysis suspicious.exe --json --yara --capa

# With LLM-powered analyst report (requires Ollama)
uv run binanalysis suspicious.exe --report --yara --llm-model qwen3.5

# Full analysis: decompilation + all integrations
uv run binanalysis suspicious.exe --decompile ghidra --json --yara --capa --report
```

The tool prints a structured analysis to the terminal with a final **MALICIOUS / LIKELY MALICIOUS / SUSPICIOUS / No strong indicators** verdict. Add `--json` to save a machine-readable report for SIEM ingestion. Add `--report` to generate a natural-language investigation report via a local LLM. Use `--yara` and `--capa` flags to enable optional signature and capability detection (they auto-download rules on first use).

> **Note:** This tool performs static analysis — it works best on **unpacked binaries**. If `upx` is installed, UPX-packed binaries are automatically unpacked before analysis. For other packers, unpack the binary manually first (e.g., with a sandbox dump) for best results.

---

## Why This Tool

When a suspicious executable lands on an analyst's desk, the first question is always: **what does this thing do?** Dynamic analysis (running it in a sandbox) takes time to set up and may miss behavior that only triggers under specific conditions. Static analysis -- examining the file without executing it -- can surface answers in seconds.

This tool automates the tedious parts of static analysis: computing hashes for lookup, checking for packing, cataloging suspicious API imports, extracting embedded URLs and file paths, matching behavioral patterns to known attack techniques, and producing a structured verdict. The output is designed to be read top-to-bottom by an analyst who may not be a reverse engineering specialist.

---

## Features at a Glance

| Feature | What It Does | Why It Matters |
|---------|-------------|----------------|
| **Hash computation** | MD5, SHA1, SHA256 | Look up the sample on VirusTotal, track it across cases |
| **Import hash (imphash)** | Fingerprint based on imported functions | Samples built with the same tools/builder share an imphash -- useful for clustering related samples |
| **Rich header analysis** | Identifies the compiler toolchain and build environment | Unusual compilers (MinGW cross-compiled from Linux, for example) are common in custom malware |
| **PE header analysis** | Timestamps, architecture, subsystem, security features (ASLR, DEP) | Forged timestamps or disabled security features are red flags |
| **Section analysis with entropy** | Lists every PE section and measures its randomness (entropy) | Entropy above 7.0 strongly suggests the section is packed or encrypted -- a common evasion technique |
| **Import table analysis** | Maps imported Windows APIs against 17 suspicious categories (~138 APIs) | Groups imports by attack technique (injection, credential theft, evasion, etc.) so you can see intent at a glance |
| **Export table analysis** | Lists exported functions | Relevant for DLLs; unusual exports can reveal plugin or injection capabilities |
| **Resource analysis** | Enumerates embedded resources (icons, manifests, data blobs) | Malware often hides payloads or configuration data in resources |
| **Version info extraction** | Reads claimed product name, company, description | Masquerading -- a binary claiming to be "Microsoft Excel" that imports injection APIs is suspicious |
| **TLS callback detection** | Checks for Thread Local Storage callbacks | TLS callbacks execute before the program's main entry point, a technique used to run anti-analysis code early |
| **Overlay / appended data** | Detects data appended after the PE structure | Embedded PE files, archives, or encrypted blobs hidden in the overlay |
| **Compiler and packer detection** | Identifies MSVC, MinGW, Go, Borland; detects developer language hints | Helps attribute the sample and identify cross-compilation |
| **.NET analysis** | Metadata extraction (classes, methods, assembly refs), IL decompilation via `ilspycmd` | .NET binaries can be deeply inspected; obfuscated class names and suspicious method names are flagged |
| **String extraction** | ASCII and wide (UTF-16) strings matched against 115 regex patterns across 105 threat categories | Surfaces URLs, file paths, registry keys, credentials, ransom notes, mining pool addresses, and much more |
| **Dynamic API resolution detection** | Finds API names resolved at runtime via `GetProcAddress` | Malware that hides its imports by resolving them dynamically -- this catches what the import table misses |
| **Behavioral rules** | 105 rules (98 generic + 7 specimen-specific) mapped to MITRE ATT&CK techniques | Combines import analysis, string findings, and section characteristics into high-level verdicts like "process injection" or "ransomware encryption loop" |
| **IOC extraction** | 9 extractors for URLs, domains, credentials/tokens, user agents, file paths, registry keys, OAuth endpoints, UUIDs, and environment variables | Produces a list of actionable indicators you can feed into your SIEM, firewall, or threat hunting queries |
| **YARA signature scanning** | Bundled rules + custom rule directories | Signature-based detection that complements the behavioral rules |
| **capa integration** | FLARE capa capability detection with ATT&CK mapping | Identifies what the binary *can do* (e.g., "send HTTP request", "encrypt data") independent of signatures |
| **UPX auto-unpacking** | Detects UPX-packed binaries and unpacks before analysis | Packed binaries hide their strings and imports — unpacking reveals the real payload for all downstream analysis stages |
| **Decompilation** | Radare2 (`r2pipe`) pseudocode or Ghidra headless with intelligent filtering | Ghidra output is automatically scored and filtered to show only functions that contain suspicious logic, organized by attack category |
| **LLM analyst report** | Sends analysis results to a local LLM (Ollama) for natural-language interpretation | Produces a structured investigation report with executive summary, MITRE mapping, and recommended actions |
| **Threat classification** | Final verdict combining all analysis layers | A clear MALICIOUS / LIKELY MALICIOUS / SUSPICIOUS / No strong indicators assessment |

---

## Malware Family Coverage

The behavioral rules and string patterns are designed to detect indicators across a wide range of malware families. The tool does not identify a specific family name (e.g., "this is Emotet") but rather detects the *techniques and artifacts* associated with each category:

### Infostealers
Browser credential databases (Login Data, cookies, Web Data), browser master key extraction, cryptocurrency wallets (Electrum, Exodus, MetaMask, Atomic, Coinomi, Phantom, and more), Discord and Telegram session data, FTP/SSH clients (FileZilla, WinSCP, PuTTY), email clients (Outlook, Thunderbird), VPN credentials (NordVPN, OpenVPN, ProtonVPN), password managers (KeePass, LastPass, Bitwarden, 1Password, Dashlane), and gaming platforms (Steam, Minecraft).

### Ransomware
Volume Shadow Copy deletion (`vssadmin`, `wmic`), Windows recovery disabling (`bcdedit`), backup catalog deletion (`wbadmin`), ransom note text patterns, ransomware file extensions (`.encrypted`, `.locked`, `.crypt`), cryptocurrency payment addresses (Bitcoin, Ethereum, Monero), bulk file encryption loops (file enumeration + crypto APIs), safe mode boot manipulation, and drive enumeration.

### RATs and Backdoors
Reverse shell construction (cmd.exe + socket/pipe), webcam capture APIs, audio recording, keylogging (`GetAsyncKeyState`, keyboard hooks), screenshot capture (GDI `BitBlt`), clipboard monitoring, remote desktop/VNC references, remote input simulation (`SendInput`, `keybd_event`), and named pipe C2 channels.

### Loaders and Droppers
Embedded PE files (MZ headers in strings or overlay), reflective DLL injection patterns, process hollowing (`NtUnmapViewOfSection` + suspended process creation), shellcode execution (VirtualAlloc + VirtualProtect), and drops to Temp/AppData directories.

### Rootkits
Kernel driver loading (`NtLoadDriver`), SSDT (System Service Descriptor Table) hooking, direct physical memory access (`\\.\PhysicalMemory`), physical drive access, and driver path/registry references.

### Worms
Autorun.inf creation, network share propagation (ADMIN$, IPC$, `net share`), USB/removable media spreading (`GetDriveType`), network server enumeration, UNC path access, and email worm indicators (SMTP commands).

### Crypto Miners
Stratum protocol URLs (`stratum+tcp://`), mining software names (xmrig, cpuminer, cgminer, ethminer), mining pool domains (minexmr, nanopool, 2miners, f2pool, hashvault), mining algorithms (CryptoNight, RandomX, Ethash), Monero wallet addresses, and miner CLI arguments.

### Banking Trojans
Web injection configuration (set_url, data_before, data_inject), form grabbing, HTTP request hooking for traffic interception, banking/financial institution name references, and certificate installation for man-in-the-middle attacks.

### Wipers
MBR (Master Boot Record) overwrite via direct physical drive access, mass file deletion commands (`del /s /f`, `Remove-Item -Recurse`), secure overwrite tools (cipher /w, SDelete), drive formatting, and forced system shutdown.

---

## Installation

### Basic Installation

```bash
# Clone the repository
git clone <repo-url>
cd binary-analysis-toolkit

# Install with uv (recommended)
uv sync
```

### Optional Integrations

Each integration adds detection capabilities:

```bash
# capa — capability detection mapped to MITRE ATT&CK
uv sync --extra capa

# .NET metadata extraction (for analyzing .NET binaries)
uv sync --extra dotnet

# Radare2 decompilation — pseudocode output
uv sync --extra decompile

# Install everything
uv sync --extra all
```

**Note:** `yara-python` is now included in the base installation. Just use `--yara` flag to enable signature scanning.

### External Tools (Optional)

These are standalone programs installed outside of Python:

| Tool | Purpose | Install |
|------|---------|---------|
| **UPX** | Auto-unpack UPX-packed binaries before analysis | `brew install upx` or [upx.github.io](https://upx.github.io) |
| **Radare2** | Pseudocode decompilation of native functions | `brew install radare2` or [radare.org](https://rada.re) |
| **Ghidra** | Advanced decompilation with intelligent function filtering | `brew install ghidra` or [ghidra-sre.org](https://ghidra-sre.org) |
| **ilspycmd** | .NET IL decompilation to C# source | `dotnet tool install -g ilspycmd` |

### capa and YARA Rules

Rules are downloaded automatically on first use. When you run:

- `--capa` — capa rules are auto-downloaded to `~/.local/share/binanalysis/capa-rules`
- `--yara` — 6 community YARA rule repositories are auto-cloned to `~/.local/share/binanalysis/yara-rules`

To refresh rules later, use:

```bash
# Update capa rules
uv run binanalysis file.exe --update-capa

# Update community YARA rules
uv run binanalysis file.exe --update-yara
```

---

## Usage Examples

```bash
# Basic analysis — prints results to terminal
uv run binanalysis suspicious.exe

# Save a structured JSON report alongside the binary
uv run binanalysis suspicious.exe --json

# Enable YARA signature scanning
uv run binanalysis suspicious.exe --yara

# Enable capa capability detection
uv run binanalysis suspicious.exe --capa

# Both YARA and capa
uv run binanalysis suspicious.exe --yara --capa

# Decompile with Radare2
uv run binanalysis suspicious.exe --decompile r2

# Decompile with Ghidra (filtered to suspicious functions only)
uv run binanalysis suspicious.exe --decompile ghidra

# Decompile with both backends
uv run binanalysis suspicious.exe --decompile both

# Use custom YARA rules in addition to community rules
uv run binanalysis suspicious.exe --yara --yara-rules /path/to/custom-rules

# Use a specific capa rules directory
uv run binanalysis suspicious.exe --capa --capa-rules /opt/capa-rules

# Refresh community YARA rule repos before scanning
uv run binanalysis suspicious.exe --update-yara --yara

# Refresh capa rules before scanning
uv run binanalysis suspicious.exe --update-capa --capa

# Minimal output — only verdict and critical findings
uv run binanalysis suspicious.exe --quiet

# Pipe-friendly output without ANSI color codes
uv run binanalysis suspicious.exe --no-color
```

---

## CLI Reference

```
binanalysis [-h] [--json] [--decompile {r2,ghidra,both}]
            [--capa] [--yara] [--update-capa] [--update-yara]
            [--capa-rules CAPA_RULES] [--yara-rules YARA_RULES [YARA_RULES ...]]
            [--report] [--llm-url URL] [--llm-model MODEL] [--llm-timeout SECONDS]
            [--config CONFIG] [--no-color] [--quiet] [--debug]
            file
```

| Argument | Description |
|----------|-------------|
| `file` | Path to the binary file to analyze (required, positional) |
| `--json` | Save a full JSON report as `<filename>_analysis.json` next to the binary |
| `--decompile {r2,ghidra,both}` | Enable decompilation. `r2` uses Radare2 for quick pseudocode. `ghidra` uses Ghidra headless with intelligent filtering. `both` runs both backends. |
| `--capa` | Enable capa capability detection (auto-downloads rules on first use, ~100MB) |
| `--yara` | Enable YARA signature scanning (auto-downloads 6 community rule repos on first use) |
| `--update-capa` | Download/update capa rules before analysis |
| `--update-yara` | Download/update community YARA rule repositories before analysis |
| `--capa-rules` | Path to capa rules directory (overrides config file and default) |
| `--yara-rules` | One or more additional YARA rule directories (added to community rules) |
| `--report` | Generate LLM-powered analyst report (requires Ollama or compatible API) |
| `--llm-url` | LLM API base URL (default: `http://localhost:11434`) |
| `--llm-model` | LLM model name (default: `llama3`) |
| `--llm-timeout` | LLM request timeout in seconds (default: 300) |
| `--config` | Path to a TOML configuration file (see below) |
| `--no-color` | Disable colored terminal output (useful for piping to files or other tools) |
| `--quiet` | Show only the final verdict and critical findings |
| `--debug` | Save LLM prompt to file for inspection |

---

## Configuration File

For settings you use repeatedly, create a TOML configuration file instead of passing flags every time. The tool looks for configuration in this order:

1. Path passed via `--config`
2. `binanalysis.toml` in the current directory
3. `~/.config/binanalysis/config.toml`

A default configuration file is automatically created at `~/.config/binanalysis/config.toml` on first run. The configuration includes:

```toml
[paths]
# Where capa rules are stored (auto-downloaded here if missing)
capa_rules = "~/.local/share/binanalysis/capa-rules"
# capa rules git repo (change to a mirror or fork if needed)
capa_rules_repo = "https://github.com/mandiant/capa-rules.git"
# Where community YARA rules are stored
yara_community_dir = "~/.local/share/binanalysis/yara-rules"
# Additional YARA rule directories scanned on every run
# yara_extra_dirs = ["/path/to/rules"]
# Path to Ghidra headless analyzer (auto-discovered if empty)
# ghidra_headless = ""

# Community YARA repos cloned/updated by --update-yara.
# subdir = subdirectory within the repo that contains .yar files ("." = repo root).
# Comment out or remove any repos you don't want.

[yara_repos.signature-base]
repo = "https://github.com/Neo23x0/signature-base.git"
subdir = "yara"
description = "Cobalt Strike, Go implants, webshells (Neo23x0)"

[yara_repos.yara-rules]
repo = "https://github.com/Yara-Rules/rules.git"
subdir = "."
description = "Broad malware families, packers, exploits"

[yara_repos.gcti]
repo = "https://github.com/chronicle/GCTI.git"
subdir = "YARA"
description = "APT-focused, high quality (Google)"

[yara_repos.reversinglabs]
repo = "https://github.com/reversinglabs/reversinglabs-yara-rules.git"
subdir = "yara"
description = "Large malware family signature set"

[yara_repos.eset]
repo = "https://github.com/eset/malware-ioc.git"
subdir = "."
description = "ESET research publications"

[yara_repos.elastic]
repo = "https://github.com/elastic/protections-artifacts.git"
subdir = "yara/rules"
description = "Elastic threat research"

[features]
capa = false  # opt-in via --capa flag (slow, downloads ~100MB rules on first use)
yara = false  # opt-in via --yara flag (auto-downloads community rules on first use)
# decompile = ""  # "", "r2", "ghidra", or "both"

[output]
no_color = false
quiet = false
json = false

[llm]
url = "http://localhost:11434"
model = "llama3"
timeout = 300
report = false
```

CLI flags always override config file settings. For example, `--capa` will enable capa even if the config file sets `capa = false`. You can customize repository URLs in the `[yara_repos]` section (e.g., for mirrors or private forks).

---

## Understanding the Output

This is the most important section of this document. The tool produces a lot of information; here is how to read it and what to do with it.

### Verdict System

The final section of every analysis is a **classification verdict** that combines behavioral rules, capa findings, and YARA matches into a single assessment:

| Verdict | What It Means | What To Do |
|---------|--------------|------------|
| **MALICIOUS** | Critical indicators detected (process injection, credential theft, ransomware behavior, etc.) | Escalate immediately. Quarantine the file. Begin incident response if it was found on a production system. Extract IOCs for blocking. |
| **LIKELY MALICIOUS** | Multiple high-severity indicators present | Investigate further. Cross-reference hashes on VirusTotal. Check if the binary was expected on the system. Consider dynamic analysis in a sandbox. |
| **SUSPICIOUS** | Medium-severity indicators detected | Review in context. Some legitimate software triggers medium-severity rules (e.g., an installer may enumerate files and modify the registry). Consider the source of the file and whether the behavior matches its stated purpose. |
| **No strong indicators** | No behavioral rules fired at high severity | Does not mean the file is safe. Heavily packed or obfuscated malware may evade static analysis. Consider running the sample in a sandbox for dynamic analysis. |

The verdict is deliberately conservative. A "No strong indicators" result on a packed binary is a finding in itself -- it means the malware is likely using evasion techniques that require dynamic analysis to defeat.

### Severity Levels

Every behavioral rule has a severity level that reflects how strongly it indicates malicious intent:

| Severity | Meaning | Examples |
|----------|---------|----------|
| **Critical** | Strong, direct malware indicators. Rarely seen in legitimate software. | Process hollowing, reflective DLL injection, credential database theft, ransom note text, shadow copy deletion, MBR overwrite |
| **High** | Significant suspicious behavior that warrants investigation. | Anti-debugging via NT APIs, direct syscalls (EDR bypass), PowerShell execution, URL file downloads, browser profile path access |
| **Medium** | Potentially suspicious, but also seen in legitimate software. | Crypto API usage, file enumeration, COM object creation, scheduled task strings, dynamic API resolution |
| **Low** | Informational. Worth noting but not alarming on its own. | Timing functions, base64 encoding, standard encryption APIs |

### Key Output Sections Explained

#### Hashes

```
MD5      d41d8cd98f00b204e9800998ecf8427e
SHA1     da39a3ee5e6b4b0d3255bfef95601890afd80709
SHA256   e3b0c44298fc1c149afbf4c8996fb924...
```

**What to do:** Copy the SHA256 hash and search it on [VirusTotal](https://www.virustotal.com). If the sample has been seen before, you will get immediate context. Use the hashes to track the sample in your case management system.

#### Import Hash (Imphash)

A hash computed from the imported function names and their order. Two files with the same imphash almost certainly share the same codebase or were built with the same malware builder toolkit.

**What to do:** Search the imphash on VirusTotal or in your threat intelligence platform to find related samples.

#### Rich Header

The Rich header is embedded by the Microsoft Visual Studio linker and records which compiler versions and tools were used to build the binary. The tool decodes this into human-readable product names and build numbers.

**What to do:** Check for anomalies. A binary claiming to be a modern application but compiled with an ancient toolchain is suspicious. A Rich header that is all zeros or has only one entry may have been forged. MinGW (GCC cross-compiler) is frequently used to compile Windows malware on Linux.

#### Sections

```
Name       VirtAddr    VirtSize    RawSize   Entropy  Flags
.text        0x1000     0x5000     0x5000      6.40  EXEC|READ
.data        0x6000     0x1000     0x1000      7.85  READ|WRITE
```

**What to do:**
- **Entropy above 7.0** (flagged in red): The section is very likely packed or encrypted. This is a strong indicator that the binary is trying to hide its true contents.
- **Entropy between 6.5 and 7.0** (flagged in yellow): Elevated but not conclusive. Could be compressed data or resources.
- **WRITE + EXECUTE flags together**: A section that is both writable and executable is suspicious. Legitimate software rarely needs this; malware uses it to write and then run shellcode in the same memory region.
- **Zero raw size but non-zero virtual size**: The section's content is generated at runtime, often seen in packed binaries.

#### Imports

Imported Windows API functions are grouped by attack technique category. The more categories that appear, the more capabilities the binary has.

**What to do:** Focus on the "Suspicious API Usage" subsection. If you see imports from categories like `injection`, `credential_theft`, or `process_hollowing`, the binary almost certainly has offensive capabilities. Network APIs (`WinHTTP`, `WinINet`, sockets) indicate communication capability. File enumeration + crypto APIs together are a strong ransomware signal.

#### Strings

The string analysis section shows patterns extracted from the binary's raw data, organized by category (URLs, registry keys, file paths, credentials, and many more).

**What to do:** This is where you find actionable IOCs. URLs and domains can be blocked at the firewall. Registry keys reveal persistence mechanisms. File paths show what the malware targets. Embedded credentials or tokens (GitHub PATs, Bearer tokens) are critical findings that should be revoked immediately.

#### Behavioral Rules

Each triggered rule includes a severity level, a MITRE ATT&CK category, and a plain-English description of what was detected. Rules combine multiple signals -- for example, the "process injection" rule only fires when `VirtualAllocEx`, `WriteProcessMemory`, *and* `CreateRemoteThread` are all imported together.

**What to do:** Read the descriptions. They are written to tell you *what the binary can do*, not just what APIs it imports. Use the category names (injection, credential_theft, impact, lateral_movement, etc.) to map findings to your incident response playbook.

#### IOCs (Indicators of Compromise)

A deduplicated list of extracted indicators: URLs, domains, embedded credentials, user agent strings, Windows file paths, registry keys, OAuth endpoints, UUIDs, and environment variables.

**What to do:** Feed these into your SIEM or SOAR platform. Block URLs and domains at the proxy/firewall. Search for registry keys and file paths across your endpoint fleet to find other compromised systems. Revoke any exposed tokens or credentials.

#### Capa

If capa is enabled, this section shows detected capabilities mapped to MITRE ATT&CK techniques. Capa works differently from the behavioral rules -- it analyzes the binary's actual code patterns rather than just imports and strings.

**What to do:** Pay attention to capabilities in offensive namespaces: `anti-analysis`, `collection`, `impact`, `persistence`, `exploitation`, and `communication`. Five or more offensive capabilities in a single binary is a strong malicious signal.

#### YARA

Signature-based matches from YARA rules. Results include the rule name, tags, and source file.

**What to do:** YARA matches on `packer.yar` or `antidebug_antivm.yar` are fed into the verdict calculation. Matches from custom rule sets may identify specific malware families or campaigns.

#### Decompilation (when enabled)

If you use `--decompile ghidra`, the tool does not simply dump thousands of decompiled functions. Instead, it scores every function against the suspicious indicators already discovered during analysis, then filters and categorizes only the interesting ones. Functions are grouped by attack category (e.g., "Browser Data Theft", "Network / C2", "Process Injection") with a relevance score.

**What to do:** Focus on functions with the highest scores. The `_ghidra_analysis.c` output file is organized by category, making it easy to find the code responsible for specific behaviors flagged by the behavioral rules.

---

## JSON Report

When you pass `--json`, a complete structured report is saved as `<filename>_analysis.json` in the same directory as the analyzed binary.

The JSON report contains every analysis result in machine-readable form: hashes, PE headers, sections, imports, exports, resources, version info, TLS data, overlay analysis, compiler detection, string findings, dynamic APIs, behavioral rule matches, IOCs, capa capabilities, and YARA matches.

### Example: Extract IOCs with jq

```bash
# Extract all URLs
jq '.iocs.urls[]' sample_analysis.json

# Extract all triggered behavioral rules at critical severity
jq '.behavior.behaviors[] | select(.severity == "critical")' sample_analysis.json

# Get the verdict-relevant stats
jq '{hashes: .hashes, behavior_count: (.behavior.behaviors | length), capa_count: (.capa | length)}' sample_analysis.json
```

The JSON format is suitable for ingestion into SIEM platforms (Splunk, Elastic), SOAR playbooks, or custom analysis pipelines.

---

## Architecture

The analyzer uses a pluggable format-dispatch architecture. Binary format detection automatically routes to the appropriate `FormatHandler`:

```
Binary File
    ↓
Format Detection (PE / ELF / Mach-O architecture)
    ↓
Format-Specific Handler (PE today, ELF/Mach-O ready)
    ↓
Shared Pipeline (all formats)
```

For PE binaries, the analysis pipeline is:

```
1.  Hash computation (MD5, SHA1, SHA256)
2.  Import hash (imphash)
3.  PE header analysis (timestamps, architecture, security features)
4.  Rich header analysis (compiler toolchain)
5.  Section analysis (entropy, permissions)
6.  Import table analysis (suspicious API categorization)
7.  Export table analysis
8.  Resource analysis
9.  Version info extraction
10. TLS callback detection
11. Overlay / appended data analysis
12. Compiler / packer detection
13. .NET analysis (if applicable: metadata + IL decompilation)
14. String extraction and pattern matching (115+ patterns)
    +-- Dynamic API resolution detection
    +-- Generic behavioral rules (98 rules)
    +-- PE-specific specimen rules (7 rules)
    +-- IOC extraction (9 extractors)
    +-- capa capability detection (optional, --capa flag)
    +-- YARA signature scanning (optional, --yara flag)
    +-- Decompilation with intelligent filtering (optional)
15. Threat classification and verdict
```

Steps 1-13 gather format-specific data. Step 14 builds an `AnalysisContext` that aggregates all findings into a single object, which is then passed to the behavioral rule engine, IOC extractors, and (if enabled) the Ghidra decompiler's intelligent filter. The filter uses the context to dynamically derive search keywords, so it adapts to whatever malware family is being analyzed without any hardcoded family-specific logic.

---

## Contributing

### Adding Behavioral Rules

Behavioral rules are split into two categories:

**Generic rules** (all binary types) — Located in `binanalysis/formats/pe/rules/generic.py`:

```python
Rule("my_new_rule", "category", "high",
     "Description of what this detects",
     lambda ctx: ctx.has_import("SomeAPI") and ctx.has_finding("some_string_category"))
```

**Specimen-specific rules** (PE family detection) — Located in `binanalysis/formats/pe/rules/specimen.py` for PE-specific malware family detection.

The `AnalysisContext` provides these convenience methods:
- `ctx.has_import("APIName")` -- checks if any imported function matches
- `ctx.has_all_imports("API1", "API2")` -- checks that all listed APIs are imported
- `ctx.has_string_containing("substring")` -- searches all extracted strings
- `ctx.has_finding("category")` -- checks if the string pattern matcher found this category
- `ctx.any_section(predicate)` -- tests a condition against all PE sections

### Adding String Patterns

String patterns are defined in `binanalysis/config.py` as `StringPattern` dataclass instances. Each pattern includes:

```python
StringPattern(pattern, category, score, requires=[...])
```

- `pattern`: regex pattern to match
- `category`: name for the finding category
- `score`: integer weight for severity scoring
- `requires`: optional list of categories that must be present for this to activate

Behavioral rules reference categories via `ctx.has_finding("category_name")`.

### Adding YARA Rules

Place `.yar` or `.yara` files in `binanalysis/yara_rules/` for bundled rules, or configure custom directories:

- Via `--yara-rules` CLI flag
- Via `yara_extra_dirs` in `~/.config/binanalysis/config.toml`
- Community rules are auto-downloaded to `~/.local/share/binanalysis/yara-rules` when using `--yara`

### Adding IOC Extractors

IOC extractors are defined in `binanalysis/ioc.py` as `IOCExtractor` instances. Each extractor pulls a specific indicator type from the analysis context:

```python
IOCExtractor("key", "Display Name", "severity", lambda ctx: [...])
```

### Adding a New Binary Format

The framework is ready for ELF and Mach-O support. To add a new format:

1. Create `binanalysis/formats/<name>/` directory
2. Implement a `FormatHandler` with `analyze(filepath) -> dict`
3. Register it: `register_format(FormatHandler(...))`
4. Add format-specific rules in `binanalysis/formats/<name>/rules/`

---

## License

*License information to be added.*
