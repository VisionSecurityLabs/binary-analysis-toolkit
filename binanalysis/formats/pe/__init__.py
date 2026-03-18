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

    from binanalysis.formats.pe.dotnet_analyzer import run_dotnet_analysis
    results["dotnet"] = run_dotnet_analysis(filepath, pe)

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
        dotnet=results["dotnet"],
    )


def get_pe_rules():
    return PE_RULES


register_format(FormatHandler(
    name="PE",
    magic_check=lambda data: data[:2] == b'MZ',
    analyze=analyze_pe,
    get_rules=get_pe_rules,
))
