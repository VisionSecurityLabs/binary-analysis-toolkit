---
title: Malware Collection & Detection Enrichment Pipeline
---

```mermaid
flowchart TD
    subgraph Stage1["Stage 1 — Collect Samples"]
        A1[collect_samples.py] -->|"MalwareBazaar API\n(Auth-Key required)"| A2[Query by malware tag]
        A2 --> A3[Download ZIP archives]
        A3 --> A4[Extract PE files\nValidate SHA256 + MZ magic\nEnforce 50 MB size cap]
        A4 --> A5[("samples/*.exe")]
    end

    subgraph Stage2["Stage 2 — Batch Analyze"]
        B1[batch_analyze.py] --> B2[Discover *.exe in samples dir]
        B2 --> B3[Parallel workers\nsubprocess → binanalysis]
        B3 -->|per sample| B4["*_analysis.json\n*_analysis.html"]
        B3 --> B5[batch_summary.json]
    end

    subgraph Stage3["Stage 3 — Aggregate Results"]
        C1[aggregate_results.py] --> C2[Load *_analysis.json reports]
        C2 --> C3[Rule coverage stats]
        C2 --> C4[Uncovered API combos]
        C2 --> C5[Recurring strings\nURLs / registry keys / mutexes]
        C2 --> C6[C2 IOC clusters\ndomains / IPs]
        C3 & C4 & C5 & C6 --> C7[enrichment_report.json]
    end

    subgraph Stage4["Stage 4 — Generate Rules"]
        D1[generate_rules.py] --> D2[Read enrichment_report.json]
        D2 --> D3["generated.py\n(behavioral rules)"]
        D2 --> D4["generated_patterns.py\n(string patterns)"]
        D2 --> D5["generated_ioc.py\n(IOC extractors)"]
        D3 & D4 & D5 --> D6[Auto-loaded by\nbinanalysis engine]
    end

    subgraph Stage5["Stage 5 — Validate"]
        F1[validate_rules.py] --> F2[Run binanalysis on\nknown-clean PEs]
        F2 --> F3{Generated rule\nfires?}
        F3 -->|Yes| F4[Auto-remove\nfalse positive rule]
        F3 -->|No| F5[Rule passes]
    end

    Stage1 --> Stage2 --> Stage3 --> Stage4 --> Stage5
    Stage5 -.->|"re-run to verify\nimproved coverage"| Stage2

    subgraph Config["Configuration"]
        E1[".env — API keys\nBAZAAR_AUTH_KEY\nMALSHARE_API_KEY\nVT_API_KEY"]
        E2[".env.sample — template"]
        E3["Env overrides\nSAMPLES_DIR\nBATCH_WORKERS"]
    end

    Config -.-> Stage1
    Config -.-> Stage2
```

## Quick Start (full pipeline)

```bash
cp .env.sample .env
# Edit .env and set BAZAAR_AUTH_KEY

# Run everything: collect → analyze → aggregate → generate → validate
uv run python pipeline/run.py --tags AgentTesla --limit 50 --clean-dir clean_samples/

# Multiple families with capa + YARA
uv run python pipeline/run.py --tags Emotet Remcos AgentTesla --limit 100 --workers 4 --capa --yara --clean-dir clean_samples/

# Preview generated rules without writing
uv run python pipeline/run.py --tags AgentTesla --limit 50 --dry-run

# Re-analyze existing samples (skip download)
uv run python pipeline/run.py --skip-collect --samples samples/

# Only re-aggregate and regenerate (skip download + analysis)
uv run python pipeline/run.py --skip-collect --skip-analyze --samples samples/
```

## Setup

```bash
cp .env.sample .env
# Edit .env and set BAZAAR_AUTH_KEY (required)
```

## Run

### Stage 1 — Collect Samples

```bash
uv run python pipeline/collect_samples.py --tag AgentTesla --limit 50
uv run python pipeline/collect_samples.py --tag Emotet Remcos --limit 100 --out samples/
```

### Stage 2 — Batch Analyze

```bash
uv run python pipeline/batch_analyze.py --samples samples/ --workers 4
uv run python pipeline/batch_analyze.py --samples samples/ --workers 2 --capa --yara
```

### Stage 3 — Aggregate Results

```bash
uv run python pipeline/aggregate_results.py --reports samples/ --output enrichment_report.json
```

### Stage 4 — Generate Rules

```bash
# Preview what would be generated
uv run python pipeline/generate_rules.py --report enrichment_report.json --dry-run

# Generate rule files (auto-loaded by binanalysis on next run)
uv run python pipeline/generate_rules.py --report enrichment_report.json

# Adjust minimum prevalence threshold (default: 20%)
uv run python pipeline/generate_rules.py --report enrichment_report.json --min-pct 15
```

Generated files are auto-loaded by the engine when present:
- `binanalysis/formats/pe/rules/generated.py` — behavioral rules
- `binanalysis/formats/pe/rules/generated_specimen.py` — family-specific rules
- `binanalysis/generated_patterns.py` — string patterns
- `binanalysis/generated_ioc.py` — IOC extractors

### Stage 5 — Validate Against Clean Files

```bash
# Fetch clean PEs (SysInternals + NirSoft) — only needed once
uv run python pipeline/fetch_clean_samples.py --out clean_samples/

# Validate and auto-remove false positive rules
uv run python pipeline/validate_rules.py --clean-dir clean_samples/

# Report only (don't remove rules)
uv run python pipeline/validate_rules.py --clean-dir clean_samples/ --report-only
```

If `--clean-dir` is empty when running `run.py`, clean samples are fetched automatically.
Any generated rule that fires on a clean file is automatically removed.

Re-run Stage 2 + 3 after validating to verify improved coverage.
