"""Decompiler integration — r2pipe (radare2) and Ghidra headless backends."""

import subprocess
import os
import re
import logging
from pathlib import Path

from binanalysis.output import heading, subheading, info, warn, detail

try:
    import r2pipe
    HAS_R2 = True
except ImportError:
    HAS_R2 = False

logger = logging.getLogger(__name__)

def _find_ghidra_headless() -> Path:
    """Locate analyzeHeadless: env var > PATH > common install locations."""
    env = os.environ.get("GHIDRA_HEADLESS")
    if env:
        return Path(env)
    # Check PATH
    import shutil
    on_path = shutil.which("analyzeHeadless")
    if on_path:
        return Path(on_path)
    # Common install locations
    candidates = [
        Path("/opt/homebrew/opt/ghidra/libexec/support/analyzeHeadless"),  # macOS Homebrew
        Path("/usr/share/ghidra/support/analyzeHeadless"),                 # Linux package
        Path("/opt/ghidra/support/analyzeHeadless"),                       # Linux manual
    ]
    for p in candidates:
        if p.exists():
            return p
    return candidates[0]  # fallback, existence checked later

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
    """Write DecompileToFile.java to GHIDRA_SCRIPT_DIR if it doesn't already exist."""
    GHIDRA_SCRIPT_DIR.mkdir(parents=True, exist_ok=True)
    if not GHIDRA_SCRIPT_PATH.exists():
        GHIDRA_SCRIPT_PATH.write_text(_GHIDRA_SCRIPT_CONTENT)
        logger.debug("Wrote Ghidra script to %s", GHIDRA_SCRIPT_PATH)


def r2_pseudocode(
    filepath: Path,
    func_name: str = "main",
    max_funcs: int = 20,
) -> dict:
    """Decompile functions using radare2's pdc command.

    Returns:
        {"functions": [{"name": ..., "address": ..., "pseudocode": ...}], "total_functions": int}
    """
    if not HAS_R2:
        info("r2pipe not installed — skipping radare2 pseudocode (uv add r2pipe)")
        return {}

    heading("RADARE2 PSEUDOCODE")

    results = []
    r2 = None
    try:
        r2 = r2pipe.open(str(filepath), flags=["-2"])
        info("Analyzing binary (this may take a moment)...")
        r2.cmd("aa")  # basic analysis only — "aaa" hangs on large binaries

        func_list = r2.cmdj("aflj") or []
        total = len(func_list)

        if func_name:
            # Decompile only the named function
            target = next(
                (f for f in func_list if f.get("name", "") == func_name),
                None,
            )
            if target is None:
                warn(f"Function '{func_name}' not found — decompiling all up to {max_funcs}")
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

    return {"functions": results, "total_functions": total if "total" in dir() else 0}


def ghidra_decompile(filepath: Path, output_dir: Path | None = None) -> dict:
    """Decompile a binary using Ghidra's headless analyzer.

    Returns:
        {"output_file": str, "function_count": int, "success": bool}
    """
    if not GHIDRA_HEADLESS.exists():
        warn(f"Ghidra not found at {GHIDRA_HEADLESS}")
        warn("Install via: brew install ghidra")
        return {"output_file": "", "function_count": 0, "success": False}

    output_dir = output_dir or filepath.parent
    output_path = output_dir / f"{filepath.stem}_ghidra_decompiled.c"

    _ensure_ghidra_script()

    heading("GHIDRA DECOMPILATION")
    info(f"Binary: {filepath}")
    info(f"Output: {output_path}")

    pid = os.getpid()
    proj_dir = Path(f"/tmp/ghidra_proj_{pid}")
    proj_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        str(GHIDRA_HEADLESS),
        str(proj_dir),
        "proj",
        "-import", str(filepath),
        "-postScript", "DecompileToFile.java", str(output_path),
        "-scriptPath", str(GHIDRA_SCRIPT_DIR),
        "-deleteProject",
        "-max-cpu", "2",
    ]

    function_count = 0
    success = False
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )

        combined_output = result.stdout + result.stderr
        match = re.search(r"Decompiled (\d+) functions", combined_output)
        if match:
            function_count = int(match.group(1))

        if result.returncode == 0:
            success = True
            info(f"Decompiled {function_count} functions")
            detail("Output file", str(output_path))
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
        # Clean up temp project dir
        try:
            import shutil
            if proj_dir.exists():
                shutil.rmtree(proj_dir, ignore_errors=True)
        except Exception:
            pass

    return {
        "output_file": str(output_path) if success else "",
        "function_count": function_count,
        "success": success,
    }


def run_decompilation(filepath: Path, backend: str = "both") -> dict:
    """Orchestrate decompilation using one or both backends.

    Args:
        filepath: Path to the binary to decompile.
        backend: One of "r2", "ghidra", or "both".

    Returns:
        Combined results dict with keys "r2" and/or "ghidra".
    """
    results = {}

    if backend in ("r2", "both"):
        results["r2"] = r2_pseudocode(filepath)

    if backend in ("ghidra", "both"):
        results["ghidra"] = ghidra_decompile(filepath)

    return results
