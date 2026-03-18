"""LLM-powered analyst report generation via Ollama-compatible API."""

import json
import logging
import urllib.request
import urllib.error
from pathlib import Path

from binanalysis.output import heading, subheading, info, warn, detail

logger = logging.getLogger(__name__)

DEFAULT_URL = "http://localhost:11434"
DEFAULT_MODEL = "llama3"


def _build_prompt(results: dict, filepath: Path) -> str:
    """Build the analysis prompt from structured results.

    We send a condensed version of the results to stay within context limits.
    """
    # Build a focused summary instead of dumping everything
    sections = []

    sections.append(f"# Static Analysis Results for: {filepath.name}\n")

    # Hashes
    if results.get("hashes"):
        h = results["hashes"]
        sections.append(f"## Hashes\nMD5: {h.get('md5', 'N/A')}\nSHA256: {h.get('sha256', 'N/A')}")

    # Imphash
    if results.get("imphash", {}).get("imphash"):
        sections.append(f"## Import Hash\n{results['imphash']['imphash']}")

    # PE Headers summary
    if results.get("pe_headers"):
        ph = results["pe_headers"]
        sections.append(f"## PE Headers\nArchitecture: {ph.get('machine', 'N/A')}\n"
                       f"Subsystem: {ph.get('subsystem', 'N/A')}\n"
                       f"Timestamp: {ph.get('timestamp', 'N/A')}")

    # Compiler
    if results.get("compiler"):
        sections.append(f"## Compiler\n{json.dumps(results['compiler'], default=str)}")

    # Sections with high entropy
    if results.get("sections"):
        suspicious_sections = []
        for s in results["sections"] if isinstance(results["sections"], list) else []:
            if isinstance(s, dict) and s.get("entropy", 0) > 6.5:
                suspicious_sections.append(f"{s.get('name', '?')}: entropy={s.get('entropy', 0):.2f}")
        if suspicious_sections:
            sections.append(f"## High-Entropy Sections\n" + "\n".join(suspicious_sections))

    # Imports — just the suspicious categories found
    if results.get("imports"):
        imp = results["imports"]
        if isinstance(imp, dict) and imp.get("suspicious"):
            sections.append(f"## Suspicious Import Categories\n{json.dumps(imp['suspicious'], default=str, indent=2)}")

    # Version info
    if results.get("version_info") and isinstance(results["version_info"], dict):
        vi = results["version_info"]
        if vi.get("string_file_info"):
            sections.append(f"## Version Info\n{json.dumps(vi['string_file_info'], default=str, indent=2)}")

    # Overlay
    if results.get("overlay") and isinstance(results["overlay"], dict):
        ov = results["overlay"]
        if ov.get("has_overlay"):
            sections.append(f"## Overlay Data\nSize: {ov.get('size', 0)} bytes, "
                          f"Entropy: {ov.get('entropy', 0):.2f}, "
                          f"Type: {ov.get('detected_type', 'unknown')}")

    # .NET metadata
    if results.get("dotnet") and isinstance(results["dotnet"], dict) and results["dotnet"]:
        dn = results["dotnet"]
        dn_summary = {}
        if dn.get("module"): dn_summary["module"] = dn["module"]
        if dn.get("suspicious_methods"): dn_summary["suspicious_methods"] = dn["suspicious_methods"]
        if dn.get("suspicious_classes"): dn_summary["suspicious_classes"] = dn["suspicious_classes"]
        if dn_summary:
            sections.append(f"## .NET Metadata\n{json.dumps(dn_summary, default=str, indent=2)}")

    # Strings — just categories and counts, plus a sample of values
    if results.get("strings"):
        str_summary = {}
        for category, findings in results["strings"].items():
            if isinstance(findings, list) and findings:
                values = [f.get("value", f) if isinstance(f, dict) else str(f) for f in findings[:5]]
                str_summary[category] = {"count": len(findings), "samples": values}
        if str_summary:
            sections.append(f"## String Findings\n{json.dumps(str_summary, default=str, indent=2)}")

    # Dynamic APIs
    if results.get("dynamic_apis") and isinstance(results["dynamic_apis"], list):
        apis = results["dynamic_apis"]
        if apis:
            sections.append(f"## Dynamically Resolved APIs\n{json.dumps(apis[:30], default=str)}")

    # Behavioral rules
    if results.get("behavior", {}).get("behaviors"):
        behaviors = results["behavior"]["behaviors"]
        sections.append(f"## Behavioral Rule Matches ({len(behaviors)} total)")
        for b in behaviors:
            sections.append(f"- [{b.get('severity', 'unknown').upper()}] {b.get('description', 'N/A')} "
                          f"(ATT&CK: {b.get('category', 'N/A')})")

    # IOCs
    if results.get("iocs"):
        iocs = results["iocs"]
        ioc_summary = {}
        for key, values in iocs.items():
            if isinstance(values, list) and values:
                ioc_summary[key] = values[:20]  # cap per category
        if ioc_summary:
            sections.append(f"## Extracted IOCs\n{json.dumps(ioc_summary, default=str, indent=2)}")

    # Capa
    if results.get("capa") and isinstance(results["capa"], list) and results["capa"]:
        capa_summary = [{"name": c.get("name"), "namespace": c.get("namespace"), "att&ck": c.get("att&ck")}
                       for c in results["capa"][:20]]
        sections.append(f"## Capa Capabilities ({len(results['capa'])} total)\n{json.dumps(capa_summary, default=str, indent=2)}")

    # YARA
    if results.get("yara") and isinstance(results["yara"], list) and results["yara"]:
        yara_summary = [{"rule": y.get("rule"), "source": y.get("source")} for y in results["yara"]]
        sections.append(f"## YARA Matches\n{json.dumps(yara_summary, default=str, indent=2)}")

    # Decompilation summary (if available — just the category names and function count)
    if results.get("decompilation") and isinstance(results["decompilation"], dict):
        dec = results["decompilation"]
        if dec.get("ghidra", {}).get("interesting_functions"):
            funcs = dec["ghidra"]["interesting_functions"]
            sections.append(f"## Decompiled Functions of Interest ({len(funcs)} functions)")
            for f in funcs[:15]:
                sections.append(f"- [{f.get('category', 'unknown')}] {f.get('name', '?')} (score: {f.get('score', 0)})")

    return "\n\n".join(sections)


_SYSTEM_PROMPT = """\
You are a senior malware analyst writing an investigation report for CERT/SOC analysts \
who may not be experts in reverse engineering. Your task is to analyze the static analysis \
results provided and produce a clear, actionable report.

Write in plain English. Explain technical concepts briefly when you use them. \
Focus on WHAT the binary does, WHY it is suspicious/malicious, and WHAT the analyst should do next.

Structure your report as:

1. **Executive Summary** (2-3 sentences: what is this binary, what does it do, how dangerous is it)
2. **Malware Classification** (what family/type: stealer, RAT, ransomware, loader, etc. — based on observed behaviors)
3. **Capabilities** (bullet list of what the binary can do, grouped by attack phase)
4. **Indicators of Compromise** (actionable IOCs: URLs, domains, IPs, file paths, registry keys, tokens — ready for blocking/hunting)
5. **MITRE ATT&CK Mapping** (techniques observed, in a simple table)
6. **Recommended Actions** (specific steps: what to block, what to search for, what to revoke, whether dynamic analysis is needed)
7. **Confidence Assessment** (how confident are you in this assessment, what could change it)

Keep the report concise but thorough. Prioritize actionable intelligence over technical details.\
"""


def generate_llm_report(
    results: dict,
    filepath: Path,
    llm_url: str = DEFAULT_URL,
    llm_model: str = DEFAULT_MODEL,
    timeout: int = 300,
    debug: bool = False,
) -> str | None:
    """Send analysis results to LLM and return the generated report."""
    heading("LLM ANALYST REPORT")
    info(f"Model: {llm_model}")
    info(f"Endpoint: {llm_url}")

    analysis_text = _build_prompt(results, filepath)

    if debug:
        prompt_path = filepath.parent / f"{filepath.stem}_llm_prompt.md"
        with open(prompt_path, "w", encoding="utf-8") as f:
            f.write("# System Prompt\n\n")
            f.write(_SYSTEM_PROMPT)
            f.write("\n\n---\n\n# User Prompt\n\n")
            f.write(analysis_text)
            f.write("\n")
        info(f"Debug: prompt saved to {prompt_path}")
        info(f"Prompt length: {len(analysis_text)} chars")

    # Use Ollama native chat API
    api_url = f"{llm_url.rstrip('/')}/api/chat"

    payload = {
        "model": llm_model,
        "messages": [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": f"Analyze the following static analysis results and produce an investigation report:\n\n{analysis_text}"},
        ],
        "options": {"temperature": 0.3},
        "stream": False,
    }

    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        api_url,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    info("Sending analysis to LLM (this may take a minute)...")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        report_text = data["message"]["content"]

        # Save report to file
        report_path = filepath.parent / f"{filepath.stem}_report.md"
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(f"# Investigation Report: {filepath.name}\n\n")
            f.write(f"*Generated by BAT (Binary Analysis Toolkit) + {llm_model}*\n\n")
            f.write("---\n\n")
            f.write(report_text)
            f.write("\n")

        info(f"Report saved: {report_path}")

        # Also print to terminal
        subheading("Report Preview")
        # Print first ~80 lines to terminal
        lines = report_text.split("\n")
        for line in lines[:80]:
            print(f"    {line}")
        if len(lines) > 80:
            info(f"... ({len(lines) - 80} more lines in {report_path})")

        return report_text

    except urllib.error.URLError as exc:
        warn(f"Could not connect to LLM at {api_url}: {exc.reason}")
        info("Is Ollama running? Start it with: ollama serve")
        info(f"Then pull a model: ollama pull {llm_model}")
        return None
    except KeyError:
        warn("Unexpected response format from LLM API")
        logger.debug("Response: %s", data)
        return None
    except Exception as exc:
        warn(f"LLM report generation failed: {exc}")
        return None
