"""Self-contained HTML report generation."""

from __future__ import annotations

import html
from pathlib import Path

# ---------------------------------------------------------------------------
# CSS
# ---------------------------------------------------------------------------

_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }

body {
    background: #0d1117;
    color: #c9d1d9;
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    font-size: 14px;
    line-height: 1.6;
}

a { color: #58a6ff; text-decoration: none; }

/* ── Layout ── */
.page { max-width: 1200px; margin: 0 auto; padding: 24px 16px 48px; }

/* ── Header ── */
.header {
    background: linear-gradient(135deg, #161b22 0%, #1c2128 100%);
    border: 1px solid #30363d;
    border-radius: 12px;
    padding: 28px 32px;
    margin-bottom: 24px;
    display: flex;
    flex-direction: column;
    gap: 12px;
}
.header-top { display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 12px; }
.filename { font-size: 22px; font-weight: 700; color: #e6edf3; font-family: monospace; word-break: break-all; }
.verdict-badge {
    font-size: 13px; font-weight: 700; padding: 6px 18px; border-radius: 20px;
    white-space: nowrap; text-transform: uppercase; letter-spacing: 0.5px;
    flex-shrink: 0;
}
.verdict-malicious  { background: #3d1a1a; color: #ff7b72; border: 1px solid #6e2020; }
.verdict-suspicious { background: #2d2208; color: #e3b341; border: 1px solid #5a4320; }
.verdict-clean      { background: #0d2117; color: #3fb950; border: 1px solid #1a4428; }

.meta-grid { display: flex; flex-wrap: wrap; gap: 8px 28px; }
.meta-item { font-size: 12px; color: #8b949e; }
.meta-item span { color: #c9d1d9; font-family: monospace; margin-left: 4px; }

/* ── Score bar ── */
.score-card {
    background: #161b22; border: 1px solid #30363d; border-radius: 10px;
    padding: 20px 24px; margin-bottom: 20px;
}
.score-label { font-size: 12px; color: #8b949e; margin-bottom: 8px; text-transform: uppercase; letter-spacing: 0.5px; }
.score-bar-track { background: #21262d; border-radius: 6px; height: 12px; overflow: hidden; }
.score-bar-fill  { height: 100%; border-radius: 6px; transition: width 0.3s ease; }
.score-fill-low    { background: linear-gradient(90deg, #238636, #3fb950); }
.score-fill-medium { background: linear-gradient(90deg, #9e6a03, #e3b341); }
.score-fill-high   { background: linear-gradient(90deg, #6e2020, #ff7b72); }
.score-counts { display: flex; gap: 16px; margin-top: 10px; flex-wrap: wrap; }
.count-chip { font-size: 12px; padding: 2px 10px; border-radius: 12px; font-weight: 600; }
.chip-critical { background: #3d1a1a; color: #ff7b72; }
.chip-high     { background: #2d1515; color: #f85149; }
.chip-medium   { background: #2d2208; color: #e3b341; }
.chip-low      { background: #1a2332; color: #58a6ff; }

/* ── Cards / sections ── */
.section {
    background: #161b22; border: 1px solid #30363d; border-radius: 10px;
    margin-bottom: 16px; overflow: hidden;
}
.section summary {
    display: flex; align-items: center; justify-content: space-between;
    padding: 14px 20px; cursor: pointer; user-select: none;
    list-style: none; gap: 12px;
}
.section summary::-webkit-details-marker { display: none; }
.section summary:hover { background: #1c2128; }
.section[open] summary { border-bottom: 1px solid #30363d; }
.section-title { font-size: 15px; font-weight: 600; color: #e6edf3; }
.section-badge { font-size: 11px; background: #21262d; color: #8b949e; padding: 2px 8px; border-radius: 10px; }
.chevron { color: #6e7681; font-size: 12px; transition: transform 0.15s; }
.section[open] .chevron { transform: rotate(90deg); }
.section-body { padding: 16px 20px; }

/* ── Tables ── */
table { width: 100%; border-collapse: collapse; font-size: 13px; }
th { text-align: left; padding: 8px 10px; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: #8b949e; border-bottom: 1px solid #30363d; }
td { padding: 7px 10px; border-bottom: 1px solid #21262d; vertical-align: top; }
tr:last-child td { border-bottom: none; }
tr:hover td { background: #1c2128; }
.mono { font-family: monospace; font-size: 12px; }

/* ── Severity badges ── */
.sev { font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 10px; white-space: nowrap; }
.sev-critical { background: #3d1a1a; color: #ff7b72; }
.sev-high     { background: #2d1515; color: #f85149; }
.sev-medium   { background: #2d2208; color: #e3b341; }
.sev-low      { background: #1a2332; color: #58a6ff; }
.sev-info     { background: #1a2332; color: #79c0ff; }
.sev-yara     { background: #1e1f35; color: #bc8cff; }
.sev-capa     { background: #1b2a1b; color: #56d364; }

/* ── IOC / string lists ── */
.tag-list { display: flex; flex-wrap: wrap; gap: 6px; }
.tag { font-size: 11px; font-family: monospace; background: #21262d; color: #c9d1d9; padding: 3px 8px; border-radius: 6px; word-break: break-all; }
.tag-url  { color: #79c0ff; }
.tag-ip   { color: #56d364; }
.tag-hash { color: #e3b341; }

/* ── Search box ── */
.search-bar { padding: 16px 20px 0; }
.search-input {
    width: 100%; background: #0d1117; border: 1px solid #30363d; border-radius: 8px;
    color: #c9d1d9; font-size: 13px; padding: 8px 12px; outline: none;
}
.search-input:focus { border-color: #58a6ff; }
.search-empty { color: #6e7681; font-size: 13px; padding: 12px 0; display: none; text-align: center; }

/* ── LLM report ── */
.llm-body { white-space: pre-wrap; font-size: 13px; line-height: 1.7; color: #c9d1d9; padding: 4px 0; }

/* ── ATT&CK tag ── */
.attack-tag { font-size: 10px; background: #1b2a1b; color: #56d364; padding: 1px 6px; border-radius: 8px; margin-left: 6px; }

/* ── Footer ── */
.footer { text-align: center; color: #484f58; font-size: 12px; margin-top: 32px; }

/* ── Responsive ── */
@media (max-width: 640px) {
    .header-top { flex-direction: column; }
    .verdict-badge { align-self: flex-start; }
}
"""

# ---------------------------------------------------------------------------
# JS  (search filter only)
# ---------------------------------------------------------------------------

_JS = """
document.addEventListener('DOMContentLoaded', function() {
    const input = document.getElementById('findings-search');
    if (!input) return;
    input.addEventListener('input', function() {
        const q = this.value.toLowerCase();
        const rows = document.querySelectorAll('#findings-table tr[data-row]');
        let visible = 0;
        rows.forEach(function(r) {
            const match = r.textContent.toLowerCase().includes(q);
            r.style.display = match ? '' : 'none';
            if (match) visible++;
        });
        const empty = document.getElementById('findings-empty');
        if (empty) empty.style.display = (visible === 0 && q) ? 'block' : 'none';
    });
});
"""

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _e(s) -> str:
    """HTML-escape a value."""
    return html.escape(str(s)) if s is not None else ""


def _sev_badge(severity: str) -> str:
    cls = f"sev-{severity.lower()}" if severity.lower() in ("critical", "high", "medium", "low") else "sev-info"
    return f'<span class="sev {cls}">{_e(severity.upper())}</span>'


def _verdict_class(verdict: str) -> str:
    v = verdict.lower()
    if "malicious" in v:
        return "verdict-malicious"
    if "suspicious" in v:
        return "verdict-suspicious"
    return "verdict-clean"


def _compute_verdict(behaviors: list[dict], capa: list[dict], yara: list[dict]) -> tuple[str, dict]:
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for b in behaviors:
        sev = b.get("severity", "low")
        counts[sev] = counts.get(sev, 0) + 1

    offensive_ns = {"anti-analysis", "collection", "impact", "persistence", "exploitation", "communication"}
    capa_offensive = [c for c in capa
                      if c.get("namespace", "").split("/")[0] in offensive_ns or c.get("att&ck")]
    if len(capa_offensive) >= 5:
        counts["high"] += 1
    elif len(capa_offensive) >= 3:
        counts["medium"] += 1

    yara_suspicious = [y for y in yara if y.get("source") in ("antidebug_antivm.yar", "packer.yar")]
    if yara_suspicious:
        counts["medium"] += 1

    if counts.get("critical", 0) > 0:
        verdict = "MALICIOUS"
    elif counts.get("high", 0) >= 2:
        verdict = "LIKELY MALICIOUS"
    elif counts.get("high", 0) >= 1:
        verdict = "SUSPICIOUS"
    elif counts.get("medium", 0) >= 2:
        verdict = "SUSPICIOUS"
    else:
        verdict = "CLEAN"

    return verdict, counts


def _score_pct(counts: dict) -> int:
    weights = {"critical": 40, "high": 20, "medium": 8, "low": 2}
    raw = sum(counts.get(s, 0) * w for s, w in weights.items())
    return min(100, raw)


# ---------------------------------------------------------------------------
# Section renderers
# ---------------------------------------------------------------------------

def _render_header(results: dict, filepath: Path, verdict: str, counts: dict) -> str:
    hashes = results.get("generic", {}).get("hashes", {})
    sha256 = hashes.get("sha256", "—")
    md5    = hashes.get("md5", "—")
    size   = hashes.get("size_bytes", "—")
    fmt    = results.get("format_specific", {}).get("pe_headers", {}).get("machine", "")
    ts     = results.get("format_specific", {}).get("pe_headers", {}).get("compile_time", "")

    vc = _verdict_class(verdict)
    meta_items = [
        ("SHA-256", sha256),
        ("MD5", md5),
        ("Size", f"{size:,} bytes" if isinstance(size, int) else size),
    ]
    if fmt:
        meta_items.append(("Arch", fmt))
    if ts:
        meta_items.append(("Compiled", str(ts)[:19]))

    meta_html = "".join(
        f'<div class="meta-item">{_e(k)}<span>{_e(v)}</span></div>'
        for k, v in meta_items
    )

    pct = _score_pct(counts)
    fill_cls = "score-fill-high" if pct >= 60 else ("score-fill-medium" if pct >= 25 else "score-fill-low")

    chips = "".join(
        f'<span class="count-chip chip-{sev}">{counts.get(sev, 0)} {sev.capitalize()}</span>'
        for sev in ("critical", "high", "medium", "low")
        if counts.get(sev, 0) > 0
    ) or '<span class="count-chip chip-low">No findings</span>'

    return f"""
<div class="header">
  <div class="header-top">
    <div class="filename">{_e(filepath.name)}</div>
    <div class="verdict-badge {vc}">{_e(verdict)}</div>
  </div>
  <div class="meta-grid">{meta_html}</div>
</div>
<div class="score-card">
  <div class="score-label">Threat Score</div>
  <div class="score-bar-track">
    <div class="score-bar-fill {fill_cls}" style="width:{pct}%"></div>
  </div>
  <div class="score-counts">{chips}</div>
</div>
"""


def _render_findings(behaviors: list[dict], capa: list[dict], yara: list[dict]) -> str:
    rows = []
    for b in behaviors:
        sev = b.get("severity", "low")
        rows.append((sev, "Rule", b.get("description", ""), ""))
    for c in capa:
        att = ", ".join(c.get("att&ck", [])) if c.get("att&ck") else ""
        rows.append(("capa", "CAPA", c.get("name", ""), att))
    for y in yara:
        rows.append(("yara", "YARA", y.get("rule", ""), y.get("source", "")))

    if not rows:
        return ""

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "capa": 4, "yara": 5}
    rows.sort(key=lambda r: sev_order.get(r[0], 9))

    table_rows = "".join(
        f'<tr data-row="1"><td>{_sev_badge(sev)}</td>'
        f'<td><span class="mono">{_e(kind)}</span></td>'
        f'<td>{_e(desc)}</td>'
        f'<td><span class="mono" style="font-size:11px;color:#6e7681">{_e(extra)}</span></td></tr>'
        for sev, kind, desc, extra in rows
    )

    return f"""
<details class="section" open>
  <summary>
    <span class="section-title">Findings</span>
    <span style="display:flex;align-items:center;gap:8px">
      <span class="section-badge">{len(rows)}</span>
      <span class="chevron">&#9654;</span>
    </span>
  </summary>
  <div class="search-bar">
    <input id="findings-search" class="search-input" type="text" placeholder="Search findings…">
  </div>
  <div class="section-body">
    <div id="findings-empty" class="search-empty">No matching findings.</div>
    <table id="findings-table">
      <thead><tr><th>Severity</th><th>Type</th><th>Description</th><th>Detail</th></tr></thead>
      <tbody>{table_rows}</tbody>
    </table>
  </div>
</details>
"""


def _render_pe_headers(results: dict) -> str:
    pe = results.get("format_specific", {}).get("pe_headers", {})
    if not pe:
        return ""

    fields = [
        ("Machine", pe.get("machine")),
        ("Subsystem", pe.get("subsystem")),
        ("Compile Time", str(pe.get("compile_time", ""))[:19] or None),
        ("Entry Point", pe.get("entry_point")),
        ("Image Base", pe.get("image_base")),
        ("Sections", pe.get("num_sections")),
        ("ASLR", pe.get("aslr")),
        ("DEP/NX", pe.get("dep")),
        ("CFG", pe.get("cfg")),
        ("Checksum OK", pe.get("checksum_valid")),
    ]
    rows = "".join(
        f'<tr><td style="color:#8b949e;width:160px">{_e(k)}</td><td class="mono">{_e(v)}</td></tr>'
        for k, v in fields if v is not None
    )

    sections = results.get("format_specific", {}).get("sections", [])
    sec_rows = ""
    if sections:
        sec_rows = "<br><table><thead><tr><th>Section</th><th>Virtual Size</th><th>Raw Size</th><th>Entropy</th><th>Flags</th></tr></thead><tbody>"
        for s in sections:
            ent = s.get("entropy", 0)
            ent_color = "#ff7b72" if ent > 7.0 else ("#e3b341" if ent > 6.5 else "#c9d1d9")
            sec_rows += (
                f'<tr><td class="mono">{_e(s.get("name"))}</td>'
                f'<td class="mono">{_e(s.get("virtual_size"))}</td>'
                f'<td class="mono">{_e(s.get("raw_size"))}</td>'
                f'<td class="mono" style="color:{ent_color}">{ent:.2f}</td>'
                f'<td class="mono" style="font-size:11px;color:#8b949e">{_e(s.get("characteristics",""))}</td></tr>'
            )
        sec_rows += "</tbody></table>"

    return f"""
<details class="section">
  <summary>
    <span class="section-title">PE Headers &amp; Sections</span>
    <span class="chevron">&#9654;</span>
  </summary>
  <div class="section-body">
    <table>{rows}</table>
    {sec_rows}
  </div>
</details>
"""


def _render_imports(results: dict) -> str:
    imports: dict = results.get("format_specific", {}).get("imports", {})
    if not imports:
        return ""

    suspicious_apis = {
        "VirtualAlloc", "VirtualProtect", "WriteProcessMemory", "CreateRemoteThread",
        "OpenProcess", "NtUnmapViewOfSection", "SetWindowsHookEx", "GetAsyncKeyState",
        "RegSetValueEx", "ShellExecute", "WinExec", "CreateService", "HttpSendRequest",
        "InternetOpen", "WSAConnect", "LoadLibrary", "GetProcAddress",
    }

    total = sum(len(v) for v in imports.values())
    dlls_html = []
    for dll, funcs in sorted(imports.items()):
        func_items = "".join(
            f'<span class="tag" style="color:#ff7b72">{_e(f)}</span>'
            if f in suspicious_apis
            else f'<span class="tag">{_e(f)}</span>'
            for f in sorted(funcs)
        )
        dlls_html.append(
            f'<div style="margin-bottom:14px">'
            f'<div style="font-size:12px;color:#8b949e;margin-bottom:6px;font-family:monospace">{_e(dll)}</div>'
            f'<div class="tag-list">{func_items}</div></div>'
        )

    return f"""
<details class="section">
  <summary>
    <span class="section-title">Imports</span>
    <span style="display:flex;align-items:center;gap:8px">
      <span class="section-badge">{total} functions / {len(imports)} DLLs</span>
      <span class="chevron">&#9654;</span>
    </span>
  </summary>
  <div class="section-body">{''.join(dlls_html)}</div>
</details>
"""


def _render_strings(results: dict) -> str:
    strings: dict = results.get("generic", {}).get("strings", {})
    if not strings:
        return ""

    category_labels = {
        "url": ("URLs", "tag-url"),
        "domain": ("Domains", "tag-url"),
        "ip": ("IP Addresses", "tag-ip"),
        "possible_base64": ("Possible Base64", ""),
        "github_api": ("GitHub API", ""),
        "github_pat": ("GitHub PAT", "tag-hash"),
        "ms_oauth": ("Microsoft OAuth", ""),
        "bearer_token": ("Bearer Tokens", "tag-hash"),
        "uuid": ("UUIDs", ""),
        "browser_data": ("Browser Data Paths", ""),
        "windows_path": ("Windows Paths", ""),
        "shell_command": ("Shell Commands", ""),
    }

    parts = []
    total = 0
    for cat, items in strings.items():
        if not items:
            continue
        label, tag_cls = category_labels.get(cat, (cat.replace("_", " ").title(), ""))
        tags = "".join(
            f'<span class="tag {tag_cls}">{_e(i["value"] if isinstance(i, dict) else i)}</span>'
            for i in items[:40]
        )
        overflow = f'<span class="tag" style="color:#6e7681">+{len(items)-40} more</span>' if len(items) > 40 else ""
        parts.append(
            f'<div style="margin-bottom:14px">'
            f'<div style="font-size:12px;color:#8b949e;margin-bottom:6px">{_e(label)} '
            f'<span style="color:#484f58">({len(items)})</span></div>'
            f'<div class="tag-list">{tags}{overflow}</div></div>'
        )
        total += len(items)

    if not parts:
        return ""

    return f"""
<details class="section">
  <summary>
    <span class="section-title">String Findings</span>
    <span style="display:flex;align-items:center;gap:8px">
      <span class="section-badge">{total}</span>
      <span class="chevron">&#9654;</span>
    </span>
  </summary>
  <div class="section-body">{''.join(parts)}</div>
</details>
"""


def _render_iocs(results: dict) -> str:
    iocs: dict = results.get("iocs", {})
    if not iocs:
        return ""

    parts = []
    total = 0
    for category, items in iocs.items():
        if not items:
            continue
        tag_cls = "tag-url" if category in ("urls", "domains") else ("tag-hash" if "hash" in category else "tag-ip" if category == "ips" else "")
        tags = "".join(f'<span class="tag {tag_cls}">{_e(i)}</span>' for i in items[:60])
        overflow = f'<span class="tag" style="color:#6e7681">+{len(items)-60} more</span>' if len(items) > 60 else ""
        parts.append(
            f'<div style="margin-bottom:14px">'
            f'<div style="font-size:12px;color:#8b949e;margin-bottom:6px">{_e(category.upper())} '
            f'<span style="color:#484f58">({len(items)})</span></div>'
            f'<div class="tag-list">{tags}{overflow}</div></div>'
        )
        total += len(items)

    if not parts:
        return ""

    return f"""
<details class="section">
  <summary>
    <span class="section-title">Extracted IOCs</span>
    <span style="display:flex;align-items:center;gap:8px">
      <span class="section-badge">{total}</span>
      <span class="chevron">&#9654;</span>
    </span>
  </summary>
  <div class="section-body">{''.join(parts)}</div>
</details>
"""


def _render_capa(results: dict) -> str:
    capa: list = results.get("capa", [])
    if not capa:
        return ""

    def _attack_tags(c):
        return "".join(
            f'<span class="attack-tag">{_e(a)}</span>' for a in (c.get("att&ck") or [])
        )

    rows = "".join(
        f'<tr><td style="width:40%">{_e(c.get("name",""))}</td>'
        f'<td class="mono" style="color:#8b949e;font-size:11px">{_e(c.get("namespace",""))}</td>'
        f'<td>{_attack_tags(c)}</td></tr>'
        for c in capa
    )

    return f"""
<details class="section">
  <summary>
    <span class="section-title">CAPA Capabilities</span>
    <span style="display:flex;align-items:center;gap:8px">
      <span class="section-badge">{len(capa)}</span>
      <span class="chevron">&#9654;</span>
    </span>
  </summary>
  <div class="section-body">
    <table>
      <thead><tr><th>Capability</th><th>Namespace</th><th>ATT&amp;CK</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</details>
"""


def _render_yara(results: dict) -> str:
    yara: list = results.get("yara", [])
    if not yara:
        return ""

    def _yara_tags(y):
        return "".join(
            f'<span class="tag" style="font-size:10px">{_e(t)}</span>'
            for t in (y.get("tags") or [])
        )

    rows = "".join(
        f'<tr><td class="mono">{_e(y.get("rule",""))}</td>'
        f'<td class="mono" style="color:#8b949e;font-size:11px">{_e(y.get("source",""))}</td>'
        f'<td><div class="tag-list">{_yara_tags(y)}</div></td></tr>'
        for y in yara
    )

    return f"""
<details class="section">
  <summary>
    <span class="section-title">YARA Matches</span>
    <span style="display:flex;align-items:center;gap:8px">
      <span class="section-badge">{len(yara)}</span>
      <span class="chevron">&#9654;</span>
    </span>
  </summary>
  <div class="section-body">
    <table>
      <thead><tr><th>Rule</th><th>Source</th><th>Tags</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</details>
"""


def _render_dotnet(results: dict) -> str:
    dotnet = results.get("format_specific", {}).get("dotnet")
    if not dotnet or not dotnet.get("is_dotnet"):
        return ""

    fields = [
        ("Runtime", dotnet.get("runtime_version")),
        ("Framework", dotnet.get("target_framework")),
        ("Obfuscated", dotnet.get("obfuscated")),
        ("Namespaces", len(dotnet.get("namespaces", []))),
    ]
    rows = "".join(
        f'<tr><td style="color:#8b949e;width:160px">{_e(k)}</td><td class="mono">{_e(v)}</td></tr>'
        for k, v in fields if v is not None
    )

    ns_tags = "".join(
        f'<span class="tag">{_e(n)}</span>'
        for n in (dotnet.get("namespaces") or [])[:50]
    )

    return f"""
<details class="section">
  <summary>
    <span class="section-title">.NET Analysis</span>
    <span class="chevron">&#9654;</span>
  </summary>
  <div class="section-body">
    <table>{rows}</table>
    {f'<div style="margin-top:12px"><div style="font-size:12px;color:#8b949e;margin-bottom:6px">Namespaces</div><div class="tag-list">{ns_tags}</div></div>' if ns_tags else ''}
  </div>
</details>
"""


def _render_llm(results: dict) -> str:
    report = results.get("llm_report") or results.get("report")
    if not report:
        return ""
    return f"""
<details class="section" open>
  <summary>
    <span class="section-title">LLM Analyst Report</span>
    <span class="chevron">&#9654;</span>
  </summary>
  <div class="section-body">
    <div class="llm-body">{_e(report)}</div>
  </div>
</details>
"""


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def save_html_report(results: dict, filepath: Path) -> Path:
    """Render results dict to a self-contained HTML file alongside the binary."""
    behaviors = results.get("behavior", {}).get("behaviors", [])
    capa      = results.get("capa", [])
    yara      = results.get("yara", [])

    verdict, counts = _compute_verdict(behaviors, capa, yara)

    body = (
        _render_header(results, filepath, verdict, counts)
        + _render_findings(behaviors, capa, yara)
        + _render_pe_headers(results)
        + _render_imports(results)
        + _render_strings(results)
        + _render_iocs(results)
        + _render_capa(results)
        + _render_yara(results)
        + _render_dotnet(results)
        + _render_llm(results)
    )

    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Analysis: {_e(filepath.name)}</title>
  <style>{_CSS}</style>
</head>
<body>
  <div class="page">
    {body}
    <div class="footer">Generated by binanalysis</div>
  </div>
  <script>{_JS}</script>
</body>
</html>"""

    out = filepath.parent / f"{filepath.stem}_analysis.html"
    out.write_text(page, encoding="utf-8")
    return out
