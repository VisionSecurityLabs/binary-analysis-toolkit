"""Decompiler integration — r2pipe (radare2) and Ghidra headless backends.

Instead of dumping thousands of functions, we cross-reference Ghidra's output
with the analyzer's own findings (suspicious APIs, extracted strings, IOCs)
to surface only the functions that implement interesting logic.

The filter is fully dynamic — no hardcoded specimen-specific keywords.
It adapts to whatever the analyzer found in the binary.
"""

import subprocess
import os
import re
import logging
import shutil
from pathlib import Path
from typing import TYPE_CHECKING

from bat_analyzer.output import heading, subheading, info, warn, danger, detail
from bat_analyzer.config import SUSPICIOUS_IMPORTS

if TYPE_CHECKING:
    from bat_analyzer.context import AnalysisContext

try:
    import r2pipe
    HAS_R2 = True
except ImportError:
    HAS_R2 = False

logger = logging.getLogger(__name__)


# ── Baseline suspicious API names (from config, always applied) ──

_SUSPICIOUS_API_NAMES: set[str] = set()
for _apis in SUSPICIOUS_IMPORTS.values():
    _SUSPICIOUS_API_NAMES.update(_apis)

# Generic Windows API keywords that are always interesting in decompiled code
_GENERIC_KEYWORDS = [
    # Network
    "http", "url", "socket", "connect", "send", "recv", "download",
    "InternetOpen", "WinHttp", "URLDownload",
    # Process / injection
    "CreateRemoteThread", "WriteProcessMemory", "VirtualAlloc",
    "CreateProcess", "ShellExecute", "WinExec",
    "NtCreateThread", "QueueUserAPC",
    # Crypto
    "Crypt", "BCrypt", "encrypt", "decrypt", "base64",
    # Persistence
    "RegSetValue", "RegCreateKey", "CreateService",
    "CurrentVersion\\\\Run",
    # Credentials
    "CredEnum", "CryptUnprotect", "Lsa", "password",
    # Evasion
    "IsDebuggerPresent", "CheckRemoteDebugger", "NtQueryInformation",
    "VirtualProtect",
    # Recon
    "whoami", "systeminfo", "ipconfig", "hostname", "tasklist",
]


def _build_keyword_pattern(extra_keywords: list[str] | None = None) -> re.Pattern:
    """Build regex pattern from generic keywords + any extra context-derived ones."""
    all_kw = list(_GENERIC_KEYWORDS)
    if extra_keywords:
        all_kw.extend(extra_keywords)
    # Deduplicate and sort longest-first for proper regex matching
    unique = sorted(set(all_kw), key=len, reverse=True)
    return re.compile("|".join(re.escape(kw) for kw in unique), re.IGNORECASE)


def _extract_context_keywords(ctx: "AnalysisContext") -> list[str]:
    """Derive search keywords dynamically from what the analyzer already found.

    This is what makes the filter generic — instead of hardcoding 'oauth' or
    'api.github.com', we pull the actual IOCs/strings the binary contains.
    """
    keywords = []

    # Pull interesting strings from findings — ALL categories are valuable
    # The string analysis already filtered to suspicious patterns, so anything
    # it found is worth searching for in decompiled code
    skip_categories = {"possible_base64", "json_object", "json_message_key",
                       "json_content_key", "json_branch_key", "archive_extension"}
    high_value_categories = {
        cat for cat in ctx.string_findings if cat not in skip_categories
    }
    for cat, items in ctx.string_findings.items():
        if cat in high_value_categories:
            for item in items[:10]:  # cap to avoid regex explosion
                val = item["value"]
                # Extract the meaningful part (domain from URL, key from path, etc.)
                if len(val) >= 4 and len(val) <= 80:
                    keywords.append(val)

    # Pull dynamic API names the analyzer already flagged
    for api in ctx.dynamic_apis[:30]:
        if len(api) >= 6:
            keywords.append(api)

    # Pull DLL names from imports that are uncommon / interesting
    boring_dlls = {"KERNEL32.dll", "ntdll.dll", "msvcrt.dll", "USER32.dll", "GDI32.dll",
                   "ADVAPI32.dll", "SHELL32.dll", "ole32.dll", "OLEAUT32.dll",
                   "COMCTL32.dll", "SHLWAPI.dll", "IMM32.dll"}
    for dll in ctx.imports:
        if dll not in boring_dlls and len(dll) >= 4:
            keywords.append(dll.removesuffix(".dll").removesuffix(".DLL"))

    return keywords


# ── Ghidra headless discovery ──

def _find_ghidra_headless() -> Path:
    """Locate analyzeHeadless: env var > PATH > common install locations."""
    env = os.environ.get("GHIDRA_HEADLESS")
    if env:
        return Path(env)
    on_path = shutil.which("analyzeHeadless")
    if on_path:
        return Path(on_path)
    candidates = [
        Path("/opt/homebrew/opt/ghidra/libexec/support/analyzeHeadless"),
        Path("/usr/share/ghidra/support/analyzeHeadless"),
        Path("/opt/ghidra/support/analyzeHeadless"),
    ]
    for p in candidates:
        if p.exists():
            return p
    return candidates[0]


GHIDRA_HEADLESS = _find_ghidra_headless()
GHIDRA_SCRIPT_DIR = Path("/tmp/ghidra_scripts")
GHIDRA_SCRIPT_PATH = GHIDRA_SCRIPT_DIR / "DecompileToFile.java"

_GHIDRA_SCRIPT_CONTENT = """\
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.FileWriter;
import java.io.PrintWriter;

public class DecompileToFile extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outPath = (args.length > 0) ? args[0] : "/tmp/ghidra_decompiled.c";
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);
        PrintWriter out = new PrintWriter(new FileWriter(outPath));
        out.println("// Decompiled by Ghidra " + currentProgram.getName());
        out.println();
        FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
        int count = 0;
        while (funcs.hasNext()) {
            Function func = funcs.next();
            if (monitor.isCancelled()) break;
            DecompileResults res = decomp.decompileFunction(func, 30, monitor);
            if (res.decompileCompleted()) {
                String code = res.getDecompiledFunction().getC();
                out.println("// Function: " + func.getName() + " @ " + func.getEntryPoint());
                out.println(code);
                out.println();
                count++;
            }
        }
        out.close();
        decomp.dispose();
        println("Decompiled " + count + " functions to " + outPath);
    }
}
"""


def _ensure_ghidra_script() -> None:
    GHIDRA_SCRIPT_DIR.mkdir(parents=True, exist_ok=True)
    if not GHIDRA_SCRIPT_PATH.exists():
        GHIDRA_SCRIPT_PATH.write_text(_GHIDRA_SCRIPT_CONTENT)


# ── Ghidra output parser ──

def _parse_ghidra_functions(raw_path: Path) -> list[dict]:
    """Parse the raw Ghidra .c file into individual function blocks."""
    text = raw_path.read_text(errors="replace")
    parts = re.split(r"^// Function: ", text, flags=re.MULTILINE)
    functions = []
    for part in parts[1:]:
        lines = part.split("\n", 1)
        header = lines[0].strip()
        code = lines[1] if len(lines) > 1 else ""
        match = re.match(r"(\S+)\s*@\s*(\S+)", header)
        name = match.group(1) if match else header
        addr = match.group(2) if match else ""
        functions.append({"name": name, "address": addr, "code": code.strip()})
    return functions


# ── Scoring and categorization ──

def _score_function(func: dict, keyword_pattern: re.Pattern) -> tuple[int, list[str]]:
    """Score a function by how many suspicious indicators its code contains."""
    code = func["code"]
    score = 0
    reasons = []

    # Suspicious API calls from config.py (highest weight)
    for api in _SUSPICIOUS_API_NAMES:
        if api in code:
            score += 3
            reasons.append(f"API: {api}")

    # Context-derived + generic keyword matches
    matches = keyword_pattern.findall(code)
    unique_matches = set(m.lower() for m in matches)
    for m in unique_matches:
        score += 1
        reasons.append(f"keyword: {m}")

    # Embedded URLs in decompiled code
    url_hits = re.findall(r'https?://[^\s"]{5,}', code)
    for u in url_hits[:3]:
        score += 2
        reasons.append(f"URL: {u[:60]}")

    # Windows paths
    path_hits = re.findall(r'C:\\\\[^\s"]{5,}', code)
    for p in path_hits[:3]:
        score += 1
        reasons.append(f"path: {p[:60]}")

    # Large functions are more likely to contain real logic
    if code.count("\n") > 50:
        score += 1

    return score, reasons


def _categorize_function(reasons: list[str]) -> str:
    """Assign a high-level category based on matched indicators."""
    reason_text = " ".join(reasons).lower()

    # Most specific categories first — order matters

    # ── Ransomware ──
    if any(k in reason_text for k in ["vssadmin", "shadowcopy", "ransom", "your files",
                                       "bcdedit", "wbadmin", ".encrypted", ".locked"]):
        return "Ransomware"
    if any(k in reason_text for k in ["findfirstfile", "findnextfile", "cryptencrypt",
                                       "bcryptencrypt"]) and "findfirstfile" in reason_text:
        return "Ransomware Encryption Loop"

    # ── Wiper / Destructive ──
    if any(k in reason_text for k in ["physicaldrive", "mbr", "master boot", "format",
                                       "cipher /w", "sdelete"]):
        return "Wiper / Destructive"

    # ── Rootkit ──
    if any(k in reason_text for k in ["ssdt", "ntloaddriver", "zwloaddriver",
                                       "physicalmemory", "\\device\\"]):
        return "Rootkit / Driver"

    # ── Miner ──
    if any(k in reason_text for k in ["stratum", "xmrig", "cpuminer", "mining",
                                       "cryptonight", "randomx", "ethash", "nanopool",
                                       "hashvault", "2miners"]):
        return "Crypto Miner"

    # ── Banking Trojan ──
    if any(k in reason_text for k in ["webinject", "web.*inject", "formgrab", "form.*grab",
                                       "data_before", "data_after", "data_inject", "banking"]):
        return "Banking Trojan"

    # ── Worm / Propagation ──
    if any(k in reason_text for k in ["autorun.inf", "admin$", "ipc$", "net share",
                                       "netshareenum", "netserverenum", "wnetopenum",
                                       "smtp", "mail from", "rcpt to"]):
        return "Worm / Propagation"

    # ── RAT / Backdoor ──
    if any(k in reason_text for k in ["capcreate", "webcam", "camera", "waveinopen",
                                       "microphone", "keybd_event", "mouse_event",
                                       "sendinput", "remote.*desktop", "rdp", "vnc"]):
        return "RAT / Backdoor"
    if any(k in reason_text for k in ["reverse.*shell", "bind.*shell", "cmd.exe"]) \
            and any(k in reason_text for k in ["socket", "connect", "pipe"]):
        return "RAT / Reverse Shell"

    # ── Process Injection ──
    if any(k in reason_text for k in ["createremotethread", "writeprocessmemory",
                                       "virtualallocex", "queueuserapc",
                                       "ntunmapviewofsection", "reflectiveloader"]):
        return "Process Injection"

    # ── Infostealer ──
    if any(k in reason_text for k in ["login data", "web data", "cookies", "local state",
                                       "chrome", "firefox", "edge", "brave", "opera",
                                       "logins.json", "cookies.sqlite", "key3.db", "key4.db",
                                       "encrypted_key"]):
        return "Browser Data Theft"
    if any(k in reason_text for k in ["wallet.dat", "electrum", "exodus", "metamask",
                                       "coinomi", "phantom", "keystore"]):
        return "Crypto Wallet Theft"
    if any(k in reason_text for k in ["discord", "leveldb", "telegram", "tdata", "signal"]):
        return "Messaging App Theft"
    if any(k in reason_text for k in ["filezilla", "winscp", "putty", "simontatham"]):
        return "FTP/SSH Credential Theft"
    if any(k in reason_text for k in ["thunderbird", "outlook", "\\mail\\"]):
        return "Email Data Theft"
    if any(k in reason_text for k in ["keepass", "lastpass", "1password", "bitwarden", "dashlane"]):
        return "Password Manager Theft"
    if any(k in reason_text for k in ["steam", "minecraft", "ssfn"]):
        return "Gaming Data Theft"
    if any(k in reason_text for k in ["getasynckeystate", "getkeystate", "getkeyboardstate"]):
        return "Keylogging"
    if any(k in reason_text for k in ["bitblt", "getdesktopwindow", "createcompatiblebitmap",
                                       "screenshot"]):
        return "Screen Capture"
    if any(k in reason_text for k in ["openclipboard", "getclipboarddata"]):
        return "Clipboard Theft"

    # ── Exfiltration ──
    if any(k in reason_text for k in ["webhook", "api.telegram.org/bot", "multipart/form-data"]):
        return "Data Exfiltration"

    # ── Generic categories ──
    if any(k in reason_text for k in ["http", "url", "winhttp", "internetopen", "socket",
                                       "download", "urldownload"]):
        return "Network / C2"
    if any(k in reason_text for k in ["credenum", "cryptunprotect", "lsa", "password",
                                       "token", "oauth", "sso", "cookie"]):
        return "Credential Access"
    if any(k in reason_text for k in ["crypt", "bcrypt", "encrypt", "decrypt", "base64"]):
        return "Cryptography"
    if any(k in reason_text for k in ["regsetvalue", "regcreatekey", "createservice",
                                       "currentversion"]):
        return "Persistence"
    if any(k in reason_text for k in ["isdebugger", "checkremotedebugger",
                                       "ntqueryinformation", "virtualprotect"]):
        return "Evasion / Anti-Analysis"
    if any(k in reason_text for k in ["whoami", "systeminfo", "ipconfig", "hostname", "tasklist"]):
        return "Reconnaissance"
    if any(k in reason_text for k in ["shellexecute", "createprocess", "winexec"]):
        return "Execution"
    return "Suspicious"


# ── Public API ──

def r2_pseudocode(
    filepath: Path,
    func_name: str = "main",
    max_funcs: int = 20,
) -> dict:
    """Quick pseudocode via radare2's pdc command.

    Returns:
        {"functions": [{"name", "address", "pseudocode"}], "total_functions": int}
    """
    if not HAS_R2:
        info("r2pipe not installed — skipping radare2 pseudocode (uv add r2pipe)")
        return {}

    heading("RADARE2 PSEUDOCODE")

    results = []
    total = 0
    r2 = None
    try:
        r2 = r2pipe.open(str(filepath), flags=["-2"])
        info("Analyzing binary (this may take a moment)...")
        r2.cmd("aa")

        func_list = r2.cmdj("aflj") or []
        total = len(func_list)

        if func_name:
            target = next(
                (f for f in func_list if f.get("name", "") == func_name),
                None,
            )
            if target is None:
                warn(f"Function '{func_name}' not found — decompiling top {max_funcs} by size")
                funcs_to_decompile = sorted(
                    func_list, key=lambda f: f.get("size", 0), reverse=True
                )[:max_funcs]
            else:
                funcs_to_decompile = [target]
        else:
            funcs_to_decompile = sorted(
                func_list, key=lambda f: f.get("size", 0), reverse=True
            )[:max_funcs]

        for i, func in enumerate(funcs_to_decompile, 1):
            addr = func.get("addr")
            name = func.get("name", f"fcn.{addr:#x}" if addr else "unknown")
            try:
                r2.cmd(f"s {addr}")
                pseudocode = r2.cmd("pdc")
            except Exception:
                pseudocode = f"(decompilation failed for {name})"
            results.append({
                "name": name,
                "address": hex(addr) if addr is not None else "unknown",
                "pseudocode": pseudocode,
            })
            subheading(f"[{i}/{len(funcs_to_decompile)}] {name} @ {hex(addr) if addr is not None else 'unknown'}")
            info(pseudocode[:500] + ("..." if len(pseudocode) > 500 else ""))

        detail("Functions decompiled", str(len(results)))
        detail("Total functions in binary", str(total))

    except Exception as e:
        warn(f"r2pipe decompilation failed: {e}")
        logger.exception("r2pipe error")
    finally:
        if r2 is not None:
            try:
                r2.quit()
            except Exception:
                pass

    return {"functions": results, "total_functions": total}


def ghidra_decompile(
    filepath: Path,
    ctx: "AnalysisContext | None" = None,
    output_dir: Path | None = None,
) -> dict:
    """Decompile with Ghidra, then filter to only interesting functions.

    If an AnalysisContext is provided, keywords are derived dynamically from
    the analyzer's findings (IOCs, strings, dynamic APIs). This makes the
    filter adapt to whatever malware family is being analyzed.

    Without a context, only generic Windows API indicators are used.
    """
    if not GHIDRA_HEADLESS.exists():
        warn(f"Ghidra not found at {GHIDRA_HEADLESS}")
        warn("Install via: brew install ghidra")
        return {"output_file": "", "function_count": 0, "success": False}

    # Build keyword pattern — generic + context-derived
    extra_kw = _extract_context_keywords(ctx) if ctx else []
    keyword_pattern = _build_keyword_pattern(extra_kw)
    if extra_kw:
        detail("Context-derived keywords", str(len(extra_kw)))

    output_dir = output_dir or filepath.parent
    raw_path = output_dir / f"{filepath.stem}_ghidra_raw.c"
    focused_path = output_dir / f"{filepath.stem}_ghidra_analysis.c"

    _ensure_ghidra_script()

    heading("GHIDRA DECOMPILATION")
    info("Decompiling binary (this takes ~30s)...")

    pid = os.getpid()
    proj_dir = Path(f"/tmp/ghidra_proj_{pid}")
    proj_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        str(GHIDRA_HEADLESS),
        str(proj_dir),
        "proj",
        "-import", str(filepath),
        "-postScript", "DecompileToFile.java", str(raw_path),
        "-scriptPath", str(GHIDRA_SCRIPT_DIR),
        "-deleteProject",
        "-max-cpu", "2",
    ]

    function_count = 0
    success = False
    interesting_funcs = []
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300,
        )

        combined_output = result.stdout + result.stderr
        match = re.search(r"Decompiled (\d+) functions", combined_output)
        if match:
            function_count = int(match.group(1))

        if result.returncode == 0 and raw_path.exists():
            success = True
            info(f"Decompiled {function_count} total functions")

            # ── Filter to interesting functions ──
            all_funcs = _parse_ghidra_functions(raw_path)
            scored = []
            for func in all_funcs:
                score, reasons = _score_function(func, keyword_pattern)
                if score >= 3:
                    category = _categorize_function(reasons)
                    scored.append((score, func, reasons, category))

            scored.sort(key=lambda x: x[0], reverse=True)

            # Write focused output file
            with open(focused_path, "w") as f:
                f.write(f"// FOCUSED DECOMPILATION ANALYSIS\n")
                f.write(f"// Binary: {filepath.name}\n")
                f.write(f"// {len(scored)} interesting functions out of {function_count} total\n")
                f.write(f"// Filtered by: suspicious API calls, analyzer-discovered IOCs,\n")
                f.write(f"//   strings, dynamic APIs, and generic behavioral indicators\n\n")

                by_category: dict[str, list] = {}
                for score, func, reasons, category in scored:
                    by_category.setdefault(category, []).append((score, func, reasons))

                for category in sorted(by_category, key=lambda c: max(s for s, _, _ in by_category[c]), reverse=True):
                    f.write(f"\n{'='*70}\n")
                    f.write(f"// CATEGORY: {category}\n")
                    f.write(f"{'='*70}\n\n")

                    for score, func, reasons in by_category[category]:
                        f.write(f"// ── {func['name']} @ {func['address']} ──\n")
                        f.write(f"// Score: {score} | Triggers: {', '.join(reasons[:8])}\n")
                        f.write(func["code"])
                        f.write("\n\n")

                        interesting_funcs.append({
                            "name": func["name"],
                            "address": func["address"],
                            "category": category,
                            "score": score,
                            "triggers": reasons[:8],
                        })

            # ── Display summary ──
            subheading("Interesting Functions Found")
            detail("Total decompiled", str(function_count))
            detail("Suspicious / relevant", str(len(scored)))
            info(f"Focused analysis saved to: {focused_path}")

            if scored:
                print()
                for category in sorted(by_category, key=lambda c: max(s for s, _, _ in by_category[c]), reverse=True):
                    items = by_category[category]
                    subheading(f"{category} ({len(items)} functions)")
                    for score, func, reasons in items[:5]:
                        triggers_short = ", ".join(r.split(": ", 1)[-1] for r in reasons[:4])
                        if score >= 5:
                            danger(f"{func['name']} @ {func['address']}  (score={score})  [{triggers_short}]")
                        else:
                            warn(f"{func['name']} @ {func['address']}  (score={score})  [{triggers_short}]")
                    if len(items) > 5:
                        info(f"  ... and {len(items) - 5} more")
            else:
                info("No functions matched suspicious indicators")

            # Clean up the massive raw file
            raw_path.unlink(missing_ok=True)

        else:
            warn(f"Ghidra exited with code {result.returncode}")
            if result.stderr:
                logger.debug("Ghidra stderr: %s", result.stderr[-2000:])

    except subprocess.TimeoutExpired:
        warn("Ghidra decompilation timed out after 300 seconds")
    except Exception as e:
        warn(f"Ghidra decompilation failed: {e}")
        logger.exception("Ghidra error")
    finally:
        try:
            if proj_dir.exists():
                shutil.rmtree(proj_dir, ignore_errors=True)
        except Exception:
            pass

    return {
        "output_file": str(focused_path) if success else "",
        "function_count": function_count,
        "interesting_count": len(interesting_funcs),
        "functions": interesting_funcs,
        "success": success,
    }


def run_decompilation(
    filepath: Path,
    backend: str = "both",
    ctx: "AnalysisContext | None" = None,
) -> dict:
    """Orchestrate decompilation using one or both backends.

    Args:
        filepath: Path to the binary.
        backend: "r2", "ghidra", or "both".
        ctx: AnalysisContext from the main pipeline — enables dynamic keyword filtering.
    """
    results = {}

    if backend in ("r2", "both"):
        results["r2"] = r2_pseudocode(filepath)

    if backend in ("ghidra", "both"):
        results["ghidra"] = ghidra_decompile(filepath, ctx=ctx)

    return results
