# Refactor: pe_analyzer → binanalysis (generic static binary analyzer)

## Goal
Restructure the PE-only analyzer into a format-agnostic framework. PE remains the only implemented format; architecture supports adding ELF/Mach-O later.

## Package Structure

```
binanalysis/
├── __main__.py              # CLI: auto-detect format, dispatch
├── config.py                # Shared string patterns (format-agnostic)
├── output.py                # Terminal display helpers
├── strings.py               # ASCII/wide extraction
├── context.py               # Base AnalysisContext
├── rules.py                 # Rule/IOCExtractor dataclasses + runner engine
├── ioc.py                   # IOC extractors (string-based, format-agnostic)
├── generic/
│   ├── hashes.py            # MD5/SHA1/SHA256
│   ├── entropy.py           # Section entropy checks
│   └── rules.py             # Generic rules (high entropy, string-based)
├── formats/
│   ├── __init__.py           # Format registry + auto-detection
│   └── pe/
│       ├── context.py        # PEContext(AnalysisContext)
│       ├── analysis.py       # PE headers, imports, exports, resources, TLS, compiler
│       ├── config.py         # SUSPICIOUS_IMPORTS (Windows APIs)
│       └── rules/
│           ├── generic.py    # Technique-based PE rules
│           └── specimen.py   # Family-specific PE rules
├── integrations/
│   ├── capa_runner.py
│   └── yara_runner.py
```

## Core Abstractions

- `AnalysisContext` (base): filepath, data, format_name, strings, sections, hashes, string_findings
- `PEContext(AnalysisContext)`: pe, imports, flat_imports, version_info, dynamic_apis, exports
- `FormatHandler`: name, magic_check, analyze function — registered in FORMATS list
- `detect_format(data)`: iterates FORMATS, returns matching handler

## Execution Flow

1. Read file → detect_format → get handler
2. Generic analysis (hashes, strings, pattern matching)
3. Format-specific analysis → returns typed context subclass
4. Generic rules (entropy, strings) on base context
5. Format-specific rules on typed context
6. IOC extraction (string-based)
7. Integrations (capa, yara)
8. Classify + verdict
9. Output with format banner + grouped JSON

## What Moves Where

| From | To | Reason |
|---|---|---|
| analyze_hashes | generic/hashes.py | Format-agnostic |
| analyze_strings, analyze_dynamic_apis | generic/ | Raw bytes |
| PE-specific analysis functions | formats/pe/analysis.py | PE-only |
| SUSPICIOUS_IMPORTS | formats/pe/config.py | Windows APIs |
| SUSPICIOUS_STRING_PATTERNS | config.py | Format-agnostic |
| Rules using has_import | formats/pe/rules/ | PE-specific |
| Entropy/string-only rules | generic/rules.py | Format-agnostic |
| IOC extractors | ioc.py | All string-based |
