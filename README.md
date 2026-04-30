# Binary Analysis Toolkit (BAT)

Static analysis for suspicious binaries, focused on Windows PE files. BAT inspects a sample without running it, extracts IOCs, highlights suspicious capabilities, and produces a verdict to help triage.

Python dependencies are installed with `uv sync`. Optional tools such as `Radare2`, `Ghidra`, `ilspycmd`, `UPX`, `capa`, and YARA rules enable deeper analysis.

If you are triaging a live alert, start with [docs/guide.md](docs/guide.md).

## Disclaimer

Use this toolkit only for defensive, authorized analysis. The authors assume no liability for misuse or damage caused by use of the software.

## Quick Start

```bash
git clone <repo-url>
cd binary-analysis-toolkit
uv sync

# Basic analysis
uv run binanalysis suspicious.exe

# Enable YARA or capa
uv run binanalysis suspicious.exe --yara
uv run binanalysis suspicious.exe --capa

# Decompile and generate an LLM report
uv run binanalysis suspicious.exe \
  --decompile ghidra \
  --yara \
  --capa \
  --llm-report \
  --llm-url http://ollama:11434 \
  --llm-model qwen3.5 \
  --llm-timeout 600 \
  --debug
```

BAT prints a verdict to the terminal and saves `<filename>_analysis.json` and `<filename>_analysis.html` next to the sample. `--llm-report` adds a natural-language report. `--yara` and `--capa` download rules on first use.

Static analysis works best on unpacked binaries. If `upx` is installed, BAT automatically unpacks UPX-packed samples.

## Why BAT

BAT automates the first-pass checks analysts usually do by hand:

- Compute hashes and imphash
- Inspect PE metadata, sections, entropy, imports, exports, and resources
- Extract strings and IOCs
- Match suspicious behaviors to ATT&CK-style techniques
- Optionally run YARA, capa, and decompilation
- Produce a final verdict for triage

## Key Features

- PE header, section, entropy, Rich header, import, export, resource, TLS, overlay, and version-info analysis
- .NET metadata inspection and optional `ilspycmd` decompilation
- String extraction with threat-oriented pattern matching
- Behavioral rules for common malware techniques such as injection, credential theft, persistence, exfiltration, and ransomware activity
- IOC extraction for URLs, domains, file paths, registry keys, tokens, user agents, UUIDs, and environment variables
- Optional YARA and capa integration
- Optional Radare2 or Ghidra decompilation
- Optional LLM-generated analyst report from a local or remote Ollama-compatible endpoint

## Installation

### Base install

```bash
git clone <repo-url>
cd binary-analysis-toolkit
uv sync
```

### Optional external tools

| Tool | Purpose |
| ---- | ------- |
| `upx` | Unpack UPX-packed binaries |
| `radare2` | Native pseudocode decompilation |
| `ghidra` | Headless decompilation with suspicious-function filtering |
| `ilspycmd` | .NET IL decompilation |

### Rules

- `--capa` downloads capa rules to `~/.local/share/binanalysis/capa-rules`
- `--yara` downloads community YARA repos to `~/.local/share/binanalysis/yara-rules`

Refresh them with:

```bash
uv run binanalysis file.exe --update-capa
uv run binanalysis file.exe --update-yara
```

## Usage

```bash
# Basic analysis
uv run binanalysis suspicious.exe

# YARA and capa
uv run binanalysis suspicious.exe --yara --capa

# Decompile
uv run binanalysis suspicious.exe --decompile r2
uv run binanalysis suspicious.exe --decompile ghidra
uv run binanalysis suspicious.exe --decompile both

# Custom rule directories
uv run binanalysis suspicious.exe --yara --yara-rules /path/to/custom-rules
uv run binanalysis suspicious.exe --capa --capa-rules /opt/capa-rules
```

## CLI Reference

```text
binanalysis [-h] [--decompile {r2,ghidra,both}]
            [--capa] [--yara] [--update-capa] [--update-yara]
            [--capa-rules CAPA_RULES] [--yara-rules YARA_RULES [YARA_RULES ...]]
            [--llm-report] [--llm-url URL] [--llm-model MODEL] [--llm-timeout SECONDS]
            [--config CONFIG] [--debug]
            file
```

| Argument | Description |
| -------- | ----------- |
| `file` | Binary to analyze |
| `--decompile {r2,ghidra,both}` | Run native decompilation |
| `--capa` | Enable capa capability detection |
| `--yara` | Enable YARA scanning |
| `--update-capa` | Refresh capa rules before analysis |
| `--update-yara` | Refresh YARA repos before analysis |
| `--capa-rules` | Override capa rules directory |
| `--yara-rules` | Add one or more extra YARA rule directories |
| `--llm-report` | Generate an LLM analyst report |
| `--llm-url` | LLM API base URL |
| `--llm-model` | LLM model name |
| `--llm-timeout` | LLM timeout in seconds |
| `--config` | YAML config path |
| `--debug` | Write the LLM prompt to `<filename>_llm_prompt.md` |

## Configuration

BAT loads config in this order:

1. `--config`
2. `binanalysis.yaml` in the current directory
3. `~/.config/binanalysis/config.yaml`

A default config is created on first run. Common settings:

```yaml
paths:
  capa_rules: ~/.local/share/binanalysis/capa-rules
  yara_community_dir: ~/.local/share/binanalysis/yara-rules

features:
  capa: false
  yara: false

llm:
  url: http://ollama:11434
  model: qwen3.5
  timeout: 600
  report: false
```

CLI flags override config values.

## Output

BAT combines several signals into a final verdict:

| Verdict | Meaning | Analyst action |
| ------- | ------- | -------------- |
| `MALICIOUS` | Strong direct indicators | Quarantine, isolate affected hosts, open an incident, extract IOCs |
| `LIKELY MALICIOUS` | Multiple high-confidence signals | Escalate for deeper review, validate scope, check execution evidence |
| `SUSPICIOUS` | Context-dependent findings | Verify source, signer, delivery path, and business justification |
| `No strong indicators` | Nothing conclusive from static analysis | Check for packing; move to sandboxing if entropy is high or context is poor |

Recommended reading order:

1. Verdict
2. Hashes and `imphash`
3. IOCs
4. Behavioral rules
5. Sections and entropy
6. Optional decompilation output

Packed binaries can hide imports and strings, so a weak verdict on a high-entropy sample still deserves follow-up.

## What BAT Does Not Do

BAT helps with first-pass triage. It does not replace:

- Dynamic analysis or sandbox detonation
- Endpoint telemetry, process trees, or network logs
- Full reverse engineering
- Attribution to a specific actor or malware family
- Proof that a capability was executed on a host

Use BAT to narrow the question, not to close an incident by itself.

## Reports

- JSON: best for SIEM ingestion and automation
- HTML: best for sharing and manual review
- LLM report: optional narrative summary for analysts

## Docs

- Live triage and analyst workflow: [docs/guide.md](docs/guide.md)
- Enrichment pipeline: [pipeline/README.md](pipeline/README.md)

## Contributing

Contributions are welcome. Prefer focused changes with clear rationale and tests where practical.

## License

See `LICENSE`.
