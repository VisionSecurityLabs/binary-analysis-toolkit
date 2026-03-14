# Binary Analysis Toolkit (BAT)

A command-line tool for automated static analysis of Windows PE (Portable Executable) files. It examines executables without running them, identifies malicious behavior patterns, extracts actionable indicators of compromise (IOCs), and classifies threats -- giving CERT and SOC analysts a fast, structured starting point for triage and investigation.

Written in Python. The only required dependency is `pefile`; all other integrations (capa, YARA, decompilers) are optional.

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

# Analyze a binary
uv run bat-analyzer suspicious.exe

# With JSON report
uv run bat-analyzer suspicious.exe --json

# With LLM-powered analyst report (requires Ollama)
uv run bat-analyzer suspicious.exe --report --llm-model qwen3.5

# Full analysis: decompilation + all integrations
uv run bat-analyzer suspicious.exe --decompile ghidra --json --report
```

The tool prints a structured analysis to the terminal with a final **MALICIOUS / SUSPICIOUS / No strong indicators** verdict. Add `--json` to save a machine-readable report for SIEM ingestion. Add `--report` to generate a natural-language investigation report via a local LLM.

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
| **Decompilation** | Radare2 (`r2pipe`) pseudocode or Ghidra headless with intelligent filtering | Ghidra output is automatically scored and filtered to show only functions that contain suspicious logic, organized by attack category |
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

Each integration adds detection capabilities but is not required for the core analysis:

```bash
# capa — capability detection mapped to MITRE ATT&CK
uv sync --extra capa

# YARA — signature-based scanning
uv sync --extra yara

# Radare2 decompilation — pseudocode output
uv sync --extra decompile

# Install everything
uv sync --extra all
```

### External Tools (Optional)

These are standalone programs installed outside of Python:

| Tool | Purpose | Install |
|------|---------|---------|
| **Radare2** | Pseudocode decompilation of native functions | `brew install radare2` or [radare.org](https://rada.re) |
| **Ghidra** | Advanced decompilation with intelligent function filtering | `brew install ghidra` or [ghidra-sre.org](https://ghidra-sre.org) |
| **ilspycmd** | .NET IL decompilation to C# source | `dotnet tool install -g ilspycmd` |
| **dnfile** | .NET metadata extraction (classes, methods, strings) | `pip install dnfile` |

### capa Rules

If you enable capa, you also need the rule set:

```bash
git clone --depth 1 https://github.com/mandiant/capa-rules.git /tmp/capa-rules
```

---

## Usage Examples

```bash
# Basic analysis — prints results to terminal
uv run bat-analyzer suspicious.exe

# Save a structured JSON report alongside the binary
uv run bat-analyzer suspicious.exe --json

# Decompile with Radare2
uv run bat-analyzer suspicious.exe --decompile r2

# Decompile with Ghidra (filtered to suspicious functions only)
uv run bat-analyzer suspicious.exe --decompile ghidra

# Decompile with both backends
uv run bat-analyzer suspicious.exe --decompile both

# Skip optional integrations if they are slow or not needed
uv run bat-analyzer suspicious.exe --no-capa --no-yara

# Use custom YARA rules in addition to bundled ones
uv run bat-analyzer suspicious.exe --yara-rules /path/to/rules

# Use a specific capa rules directory
uv run bat-analyzer suspicious.exe --capa-rules /opt/capa-rules

# Minimal output — only verdict and critical findings
uv run bat-analyzer suspicious.exe --quiet

# Pipe-friendly output without ANSI color codes
uv run bat-analyzer suspicious.exe --no-color
```

---

## CLI Reference

```
bat-analyzer [-h] [--json] [--decompile {r2,ghidra,both}]
            [--no-capa] [--no-yara] [--no-color] [--quiet]
            [--config CONFIG] [--capa-rules CAPA_RULES]
            [--yara-rules YARA_RULES [YARA_RULES ...]]
            file
```

| Argument | Description |
|----------|-------------|
| `file` | Path to the PE file to analyze (required, positional) |
| `--json` | Save a full JSON report as `<filename>_analysis.json` next to the binary |
| `--decompile {r2,ghidra,both}` | Enable decompilation. `r2` uses Radare2 for quick pseudocode. `ghidra` uses Ghidra headless with intelligent filtering. `both` runs both backends. |
| `--no-capa` | Skip capa capability analysis (faster if capa is installed but not needed) |
| `--no-yara` | Skip YARA signature scanning |
| `--no-color` | Disable colored terminal output (useful for piping to files or other tools) |
| `--quiet` | Show only the final verdict and critical findings |
| `--config` | Path to a TOML configuration file (see below) |
| `--capa-rules` | Path to capa rules directory (overrides config file and default `/tmp/capa-rules`) |
| `--yara-rules` | One or more additional YARA rule directories to scan (added to any configured defaults) |

---

## Configuration File

For settings you use repeatedly, create a TOML configuration file instead of passing flags every time. The tool looks for configuration in this order:

1. Path passed via `--config`
2. `bat_analyzer.toml` in the current directory
3. `~/.config/bat_analyzer/config.toml`

An example configuration file (`bat_analyzer.toml.example`) is included in the repository:

```toml
[paths]
capa_rules = "/opt/capa-rules"
yara_extra_dirs = ["/opt/yara-rules", "/home/analyst/custom-rules"]
ghidra_headless = "/opt/ghidra/support/analyzeHeadless"

[features]
capa = true
yara = true
decompile = ""  # "", "r2", "ghidra", or "both"

[output]
no_color = false
quiet = false
json = false
```

CLI flags always override config file settings. For example, `--no-capa` will disable capa even if the config file sets `capa = true`.

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

The analyzer runs a sequential pipeline, where each step builds on the results of previous steps:

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
14. String extraction and pattern matching (115 patterns)
    +-- Dynamic API resolution detection
    +-- Behavioral rule engine (105 rules)
    +-- IOC extraction (9 extractors)
    +-- capa capability detection (optional)
    +-- YARA signature scanning (optional)
    +-- Decompilation with intelligent filtering (optional)
15. Threat classification and verdict
```

Steps 1-13 gather raw data. Step 14 builds an `AnalysisContext` that aggregates all findings into a single object, which is then passed to the behavioral rule engine, IOC extractors, and (if enabled) the Ghidra decompiler's intelligent filter. The filter uses the context to dynamically derive search keywords, so it adapts to whatever malware family is being analyzed without any hardcoded family-specific logic.

---

## Contributing

### Adding Behavioral Rules

Behavioral rules live in `bat_analyzer/rules/generic.py`. Each rule is a `Rule` object with a name, ATT&CK category, severity level, description, and a check function that receives an `AnalysisContext`:

```python
Rule("my_new_rule", "category", "high",
     "Description of what this detects",
     lambda ctx: ctx.has_import("SomeAPI") and ctx.has_finding("some_string_category"))
```

The `AnalysisContext` provides these convenience methods:
- `ctx.has_import("APIName")` -- checks if any imported function matches
- `ctx.has_all_imports("API1", "API2")` -- checks that all listed APIs are imported
- `ctx.has_string_containing("substring")` -- searches all extracted strings
- `ctx.has_finding("category")` -- checks if the string pattern matcher found this category
- `ctx.any_section(predicate)` -- tests a condition against all PE sections

### Adding String Patterns

String patterns are defined in `bat_analyzer/config.py` in the `SUSPICIOUS_STRING_PATTERNS` list. Each entry is a tuple of `(regex_pattern, category_name)`. The category name is what behavioral rules reference via `ctx.has_finding("category_name")`.

### Adding YARA Rules

Place `.yar` or `.yara` files in `bat_analyzer/yara_rules/` for bundled rules, or point `--yara-rules` or the config file's `yara_extra_dirs` at your custom rule directories.

### Adding IOC Extractors

IOC extractors are defined in `bat_analyzer/rules/ioc.py`. Each extractor pulls a specific indicator type from the analysis context and defines how it should be displayed.

---

## License

*License information to be added.*
