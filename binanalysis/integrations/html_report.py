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
.verdict-benign     { background: #0d2117; color: #56d364; border: 1px solid #1a4428; }

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
th { text-align: left; padding: 8px 10px; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: #8b949e; border-bottom: 1px solid #30363d; overflow-wrap: break-word; word-break: break-word; }
td { padding: 7px 10px; border-bottom: 1px solid #21262d; vertical-align: top; overflow-wrap: break-word; word-break: break-word; }
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
    if "benign" in v:
        return "verdict-benign"
    return "verdict-clean"


def _compute_verdict(behaviors: list[dict], capa: list[dict], yara: list[dict],
                     legitimacy: dict | None = None) -> tuple[str, dict]:
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

    # Legitimacy signals can downgrade the verdict
    leg = legitimacy or {}
    leg_count = sum(1 for k in ("is_installer", "signed", "known_software", "vt_clean") if leg.get(k))
    has_strong_legitimacy = leg_count >= 2

    if counts.get("critical", 0) > 0:
        verdict = "SUSPICIOUS" if has_strong_legitimacy else "MALICIOUS"
    elif counts.get("high", 0) >= 2:
        verdict = "SUSPICIOUS" if has_strong_legitimacy else "LIKELY MALICIOUS"
    elif counts.get("high", 0) >= 1:
        verdict = "LIKELY BENIGN" if has_strong_legitimacy else "SUSPICIOUS"
    elif counts.get("medium", 0) >= 2:
        verdict = "LIKELY BENIGN" if has_strong_legitimacy else "SUSPICIOUS"
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
        kind = b.get("category", "rule").upper()
        rows.append((sev, kind, b.get("description", ""), b.get("rule", "")))
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


def _render_exports(results: dict) -> str:
    exports: list = results.get("format_specific", {}).get("exports", [])
    if not exports:
        return ""
    tags = "".join(f'<span class="tag mono">{_e(e)}</span>' for e in exports)
    return f"""
<details class="section">
  <summary>
    <span class="section-title">Exports</span>
    <span style="display:flex;align-items:center;gap:8px">
      <span class="section-badge">{len(exports)}</span>
      <span class="chevron">&#9654;</span>
    </span>
  </summary>
  <div class="section-body"><div class="tag-list">{tags}</div></div>
</details>
"""


def _render_resources(results: dict) -> str:
    resources: dict = results.get("format_specific", {}).get("resources", {})
    if not resources:
        return ""
    rows = "".join(
        f'<tr><td class="mono">{_e(name)}</td>'
        f'<td class="mono" style="color:#8b949e">{_e(meta.get("type_name",""))}</td>'
        f'<td class="mono" style="color:#6e7681">{_e(meta.get("type_id",""))}</td></tr>'
        for name, meta in resources.items()
    )
    return f"""
<details class="section">
  <summary>
    <span class="section-title">Resources</span>
    <span style="display:flex;align-items:center;gap:8px">
      <span class="section-badge">{len(resources)}</span>
      <span class="chevron">&#9654;</span>
    </span>
  </summary>
  <div class="section-body">
    <table>
      <thead><tr><th>Name</th><th>Type</th><th>ID</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
</details>
"""


def _render_version_info(results: dict) -> str:
    version: dict = results.get("format_specific", {}).get("version_info", {})
    if not version:
        return ""
    rows = "".join(
        f'<tr><td style="color:#8b949e;width:180px">{_e(k)}</td>'
        f'<td class="mono">{_e(v)}</td></tr>'
        for k, v in version.items()
    )
    return f"""
<details class="section">
  <summary>
    <span class="section-title">Version Info</span>
    <span class="chevron">&#9654;</span>
  </summary>
  <div class="section-body"><table>{rows}</table></div>
</details>
"""


def _render_tls(results: dict) -> str:
    tls: dict = results.get("format_specific", {}).get("tls", {})
    if not tls or not tls.get("callback_address"):
        return ""
    return f"""
<details class="section">
  <summary>
    <span class="section-title">TLS Callbacks</span>
    <span style="display:flex;align-items:center;gap:8px">
      <span class="sev sev-high">SUSPICIOUS</span>
      <span class="chevron">&#9654;</span>
    </span>
  </summary>
  <div class="section-body">
    <div style="color:#e3b341;font-size:13px">
      TLS callback table at <span class="mono">{_e(tls["callback_address"])}</span>
      — may execute code before entry point
    </div>
  </div>
</details>
"""


def _render_compiler(results: dict) -> str:
    compiler: dict = results.get("format_specific", {}).get("compiler", {})
    if not compiler:
        return ""
    fields = [
        ("Compiler", compiler.get("compiler")),
        ("Developer Languages", ", ".join(compiler.get("developer_languages", []))),
        ("GCC References", "Yes" if compiler.get("gcc_references") else None),
    ]
    rows = "".join(
        f'<tr><td style="color:#8b949e;width:180px">{_e(k)}</td><td class="mono">{_e(v)}</td></tr>'
        for k, v in fields if v
    )
    if not rows:
        return ""
    return f"""
<details class="section">
  <summary>
    <span class="section-title">Compiler / Toolchain</span>
    <span class="chevron">&#9654;</span>
  </summary>
  <div class="section-body"><table>{rows}</table></div>
</details>
"""


def _render_dynamic_apis(results: dict) -> str:
    apis: list = results.get("generic", {}).get("dynamic_apis", [])
    if not apis:
        return ""
    tags = "".join(f'<span class="tag mono" style="color:#ff7b72">{_e(a)}</span>' for a in apis)
    return f"""
<details class="section">
  <summary>
    <span class="section-title">Dynamically Resolved APIs</span>
    <span style="display:flex;align-items:center;gap:8px">
      <span class="section-badge">{len(apis)}</span>
      <span class="chevron">&#9654;</span>
    </span>
  </summary>
  <div class="section-body"><div class="tag-list">{tags}</div></div>
</details>
"""


def _render_decompile(results: dict) -> str:
    dec = results.get("decompile", {})
    if not dec:
        return ""

    sections = []

    # ── Ghidra ──
    ghidra = dec.get("ghidra")
    if ghidra and ghidra.get("success"):
        funcs: list[dict] = ghidra.get("functions", [])
        total = ghidra.get("function_count", 0)
        interesting = ghidra.get("interesting_count", len(funcs))
        output_file = ghidra.get("output_file", "")

        by_cat: dict[str, list[dict]] = {}
        for f in funcs:
            by_cat.setdefault(f.get("category", "Uncategorized"), []).append(f)

        rows = ""
        for cat in sorted(by_cat, key=lambda c: max(f["score"] for f in by_cat[c]), reverse=True):
            for f in by_cat[cat]:
                triggers = ", ".join(t.split(": ", 1)[-1] for t in f.get("triggers", [])[:6])
                score = f.get("score", 0)
                color = "#ff7b72" if score >= 7 else "#e3b341" if score >= 4 else "#79c0ff"
                rows += (
                    f'<tr><td><span class="mono" style="color:{color}">{_e(f["name"])}</span></td>'
                    f'<td><span class="mono" style="color:#8b949e">{_e(f.get("address",""))}</span></td>'
                    f'<td><span class="tag" style="background:#1e1f35;color:#bc8cff">{_e(cat)}</span></td>'
                    f'<td style="text-align:center;color:{color};font-weight:700">{score}</td>'
                    f'<td><span class="mono" style="font-size:11px;color:#6e7681">{_e(triggers)}</span></td></tr>'
                )

        file_note = (
            f'<div style="margin-bottom:12px;font-size:12px;color:#6e7681">'
            f'Focused output: <span class="mono">{_e(output_file)}</span></div>'
            if output_file else ""
        )
        table = (
            f'<table><thead><tr><th>Function</th><th>Address</th><th>Category</th>'
            f'<th style="text-align:center">Score</th><th>Triggers</th>'
            f'</tr></thead><tbody>{rows}</tbody></table>'
            if rows else '<p style="color:#6e7681;font-size:13px">No suspicious functions identified.</p>'
        )
        sections.append(f"""
<details class="section">
  <summary>
    <span class="section-title">Ghidra Decompilation</span>
    <span style="display:flex;align-items:center;gap:8px">
      <span class="section-badge">{interesting} / {total} functions</span>
      <span class="chevron">&#9654;</span>
    </span>
  </summary>
  <div class="section-body">{file_note}{table}</div>
</details>
""")

    # ── Radare2 ──
    r2 = dec.get("r2")
    if r2 and r2.get("success"):
        funcs_r2: list[dict] = r2.get("functions", [])
        total_r2 = r2.get("total_functions", 0)

        rows_r2 = ""
        for f in funcs_r2:
            pseudo = f.get("pseudocode", "")
            preview = _e(pseudo[:300] + ("…" if len(pseudo) > 300 else ""))
            rows_r2 += (
                f'<tr><td><span class="mono" style="color:#79c0ff">{_e(f["name"])}</span></td>'
                f'<td><span class="mono" style="color:#8b949e">{_e(f.get("address",""))}</span></td>'
                f'<td><pre style="margin:0;font-size:11px;color:#c9d1d9;white-space:pre-wrap">{preview}</pre></td></tr>'
            )

        table_r2 = (
            f'<table><thead><tr><th>Function</th><th>Address</th><th>Pseudocode</th>'
            f'</tr></thead><tbody>{rows_r2}</tbody></table>'
            if rows_r2 else '<p style="color:#6e7681;font-size:13px">No functions decompiled.</p>'
        )
        sections.append(f"""
<details class="section">
  <summary>
    <span class="section-title">Radare2 Pseudocode</span>
    <span style="display:flex;align-items:center;gap:8px">
      <span class="section-badge">{len(funcs_r2)} / {total_r2} functions</span>
      <span class="chevron">&#9654;</span>
    </span>
  </summary>
  <div class="section-body">{table_r2}</div>
</details>
""")

    return "".join(sections)


def _render_legitimacy(results: dict) -> str:
    leg: dict = results.get("legitimacy", {})
    if not leg:
        return ""

    items = []
    if leg.get("is_installer"):
        items.append(("Installer Framework", leg.get("framework", "Unknown"), "#56d364"))
    if leg.get("signed"):
        items.append(("Digitally Signed", leg.get("signer", "Unknown"), "#56d364"))
    if leg.get("known_software"):
        items.append(("Known Software Path", leg["known_software"], "#56d364"))
    if leg.get("vt_clean"):
        items.append(("VirusTotal", f"{leg.get('vt_detection', '0/0')} detections", "#56d364"))

    if not items:
        return ""

    rows = "".join(
        f'<tr><td style="color:#8b949e;width:180px">{_e(k)}</td>'
        f'<td class="mono" style="color:{color}">{_e(v)}</td></tr>'
        for k, v, color in items
    )

    return f"""
<details class="section" open>
  <summary>
    <span class="section-title">Legitimacy Signals</span>
    <span style="display:flex;align-items:center;gap:8px">
      <span class="section-badge" style="background:#0d2117;color:#3fb950">{len(items)} signals</span>
      <span class="chevron">&#9654;</span>
    </span>
  </summary>
  <div class="section-body"><table>{rows}</table></div>
</details>
"""


def _render_installer(results: dict) -> str:
    installer: dict = results.get("format_specific", {}).get("installer", {})
    if not installer or not installer.get("is_installer"):
        return ""

    fields = [
        ("Framework", installer.get("framework_full")),
        ("Version", installer.get("framework_version")),
    ]
    rows = "".join(
        f'<tr><td style="color:#8b949e;width:180px">{_e(k)}</td><td class="mono">{_e(v)}</td></tr>'
        for k, v in fields if v
    )

    return f"""
<details class="section">
  <summary>
    <span class="section-title">Installer Framework</span>
    <span style="display:flex;align-items:center;gap:8px">
      <span class="section-badge" style="background:#0d2117;color:#56d364">{_e(installer.get("framework",""))}</span>
      <span class="chevron">&#9654;</span>
    </span>
  </summary>
  <div class="section-body"><table>{rows}</table></div>
</details>
"""


def _render_manifest(results: dict) -> str:
    manifest: dict = results.get("format_specific", {}).get("manifest", {})
    if not manifest or not manifest.get("name"):
        return ""

    fields = [
        ("Assembly Name", manifest.get("name")),
        ("Version", manifest.get("version")),
        ("Description", manifest.get("description")),
        ("Execution Level", manifest.get("execution_level")),
        ("UI Access", manifest.get("ui_access")),
        ("Supported OS", ", ".join(manifest.get("supported_os", []))),
    ]
    rows = "".join(
        f'<tr><td style="color:#8b949e;width:180px">{_e(k)}</td><td class="mono">{_e(v)}</td></tr>'
        for k, v in fields if v
    )

    return f"""
<details class="section">
  <summary>
    <span class="section-title">PE Manifest</span>
    <span class="chevron">&#9654;</span>
  </summary>
  <div class="section-body"><table>{rows}</table></div>
</details>
"""


def _render_signature(results: dict) -> str:
    sig: dict = results.get("format_specific", {}).get("signature", {})
    if not sig or not sig.get("signed"):
        return ""

    fields = [
        ("Signed", "Yes"),
        ("Signer", sig.get("signer")),
        ("Issuer", sig.get("issuer")),
        ("Organization", sig.get("signer_organization")),
        ("Certificate Type", sig.get("cert_type")),
        ("Thumbprint (SHA-1)", sig.get("thumbprint")),
    ]
    rows = "".join(
        f'<tr><td style="color:#8b949e;width:180px">{_e(k)}</td><td class="mono">{_e(v)}</td></tr>'
        for k, v in fields if v
    )

    return f"""
<details class="section">
  <summary>
    <span class="section-title">Digital Signature</span>
    <span style="display:flex;align-items:center;gap:8px">
      <span class="section-badge" style="background:#0d2117;color:#56d364">SIGNED</span>
      <span class="chevron">&#9654;</span>
    </span>
  </summary>
  <div class="section-body"><table>{rows}</table></div>
</details>
"""


def _render_path_context(results: dict) -> str:
    ctx: dict = results.get("generic", {}).get("path_context", {})
    if not ctx or not ctx.get("known_software"):
        return ""

    fields = [
        ("Known Software", ctx.get("known_software")),
        ("Description", ctx.get("path_description")),
        ("Matched Path", ctx.get("matched_path")),
    ]
    rows = "".join(
        f'<tr><td style="color:#8b949e;width:180px">{_e(k)}</td><td class="mono">{_e(v)}</td></tr>'
        for k, v in fields if v
    )

    return f"""
<details class="section">
  <summary>
    <span class="section-title">File Path Context</span>
    <span style="display:flex;align-items:center;gap:8px">
      <span class="section-badge" style="background:#0d2117;color:#56d364">{_e(ctx.get("known_software",""))}</span>
      <span class="chevron">&#9654;</span>
    </span>
  </summary>
  <div class="section-body"><table>{rows}</table></div>
</details>
"""


def _render_virustotal(results: dict) -> str:
    vt: dict = results.get("virustotal", {})
    if not vt or not vt.get("found"):
        return ""

    malicious = vt.get("malicious", 0)
    ratio = vt.get("detection_ratio", "?")
    color = "#ff7b72" if malicious > 3 else ("#e3b341" if malicious > 0 else "#56d364")
    badge_bg = "#3d1a1a" if malicious > 3 else ("#2d2208" if malicious > 0 else "#0d2117")

    fields = [
        ("Detection Ratio", ratio),
        ("Threat Label", vt.get("threat_label")),
        ("Known Names", ", ".join(vt.get("known_names", []))),
        ("VT Signer", vt.get("vt_signer")),
        ("Tags", ", ".join(vt.get("tags", []))),
    ]
    rows = "".join(
        f'<tr><td style="color:#8b949e;width:180px">{_e(k)}</td><td class="mono">{_e(v)}</td></tr>'
        for k, v in fields if v
    )

    return f"""
<details class="section" open>
  <summary>
    <span class="section-title">VirusTotal</span>
    <span style="display:flex;align-items:center;gap:8px">
      <span class="section-badge" style="background:{badge_bg};color:{color}">{_e(ratio)}</span>
      <span class="chevron">&#9654;</span>
    </span>
  </summary>
  <div class="section-body"><table>{rows}</table></div>
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

    legitimacy = results.get("legitimacy", {})
    verdict, counts = _compute_verdict(behaviors, capa, yara, legitimacy=legitimacy)

    body = (
        _render_header(results, filepath, verdict, counts)
        + _render_legitimacy(results)
        + _render_findings(behaviors, capa, yara)
        + _render_virustotal(results)
        + _render_path_context(results)
        + _render_installer(results)
        + _render_manifest(results)
        + _render_signature(results)
        + _render_pe_headers(results)
        + _render_imports(results)
        + _render_exports(results)
        + _render_resources(results)
        + _render_version_info(results)
        + _render_tls(results)
        + _render_compiler(results)
        + _render_strings(results)
        + _render_dynamic_apis(results)
        + _render_iocs(results)
        + _render_capa(results)
        + _render_yara(results)
        + _render_dotnet(results)
        + _render_decompile(results)
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
    <div class="footer">Generated by binanalysis &mdash; Vision Security Labs</div>
  </div>
  <script>{_JS}</script>
</body>
</html>"""

    out = filepath.parent / f"{filepath.stem}_analysis.html"
    out.write_text(page, encoding="utf-8")
    return out
