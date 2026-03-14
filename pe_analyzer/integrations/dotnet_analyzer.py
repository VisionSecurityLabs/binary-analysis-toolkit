"""dotnet integration — .NET metadata extraction and IL decompilation."""

import subprocess
import logging
import shutil
from pathlib import Path

from pe_analyzer.output import heading, subheading, info, warn, danger, detail

try:
    import dnfile
    HAS_DNFILE = True
except ImportError:
    HAS_DNFILE = False

logger = logging.getLogger(__name__)

_SUSPICIOUS_METHOD_KEYWORDS = (
    "Decrypt", "Encrypt", "Download", "Execute", "Inject", "Shell",
    "Credential", "Password", "Steal", "Keylog", "Capture", "Upload",
    "Exfil", "Persist", "Hook", "Hide", "Obfuscat",
)

_INTERESTING_STRING_PATTERNS = (
    "http://", "https://", "ftp://", "\\\\", "cmd", "powershell",
    "/bin/", "passwd", "password", "token", "secret", "key",
    ".exe", ".dll", ".bat", ".ps1", "HKEY_", "SOFTWARE\\",
)


def is_dotnet_pe(pe) -> bool:
    """Return True if the PE has a CLR/COM descriptor header (index 14)."""
    try:
        if hasattr(pe, "DIRECTORY_ENTRY_COM_DESCRIPTOR"):
            return True
        va = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].VirtualAddress
        return va != 0
    except Exception:
        return False


def analyze_dotnet_metadata(filepath: Path) -> dict:
    """Extract .NET metadata via dnfile.

    Returns a dict with keys: module, classes, suspicious_methods,
    member_refs, assembly_refs, user_strings, resources.
    """
    if not HAS_DNFILE:
        info("dnfile not installed — skipping .NET analysis (uv add dnfile)")
        return {}

    heading("DOTNET METADATA")

    try:
        dn = dnfile.dnPE(str(filepath))
    except Exception as exc:
        warn(f"dnfile failed to parse {filepath.name}: {exc}")
        return {}

    result: dict = {}

    # ── Module name ──────────────────────────────────────────────────────────
    try:
        module_table = dn.net.mdtables.Module
        if module_table and len(module_table) > 0:
            module_name = str(module_table[0].Name)
            result["module"] = module_name
            detail("Module name", module_name)
    except Exception as exc:
        logger.debug("Could not read Module table: %s", exc)

    # ── TypeDef — classes / types ────────────────────────────────────────────
    subheading("Classes / Types")
    classes: list[str] = []
    suspicious_class_names: list[str] = []
    try:
        typedef_table = dn.net.mdtables.TypeDef
        if typedef_table:
            for row in typedef_table:
                try:
                    ns = str(row.TypeNamespace) if row.TypeNamespace else ""
                    name = str(row.TypeName) if row.TypeName else "<unnamed>"
                    full = f"{ns}.{name}" if ns else name
                    classes.append(full)

                    # Flag obfuscated names: very short or non-ASCII
                    if len(name) <= 2 or any(ord(c) > 127 for c in name):
                        suspicious_class_names.append(full)
                except Exception:
                    continue
    except Exception as exc:
        logger.debug("Could not read TypeDef table: %s", exc)

    result["classes"] = classes
    for cls in classes[:30]:
        info(cls)
    if len(classes) > 30:
        info(f"... and {len(classes) - 30} more")
    detail("Total types", str(len(classes)))

    if suspicious_class_names:
        subheading("Suspicious / Obfuscated Class Names")
        for name in suspicious_class_names[:20]:
            danger(f"Obfuscated class name: {name}")
        result["suspicious_classes"] = suspicious_class_names

    # ── MethodDef ────────────────────────────────────────────────────────────
    subheading("Method Analysis")
    suspicious_methods: list[str] = []
    total_methods = 0
    try:
        methoddef_table = dn.net.mdtables.MethodDef
        if methoddef_table:
            for row in methoddef_table:
                total_methods += 1
                try:
                    method_name = str(row.Name) if row.Name else ""
                    if any(kw.lower() in method_name.lower() for kw in _SUSPICIOUS_METHOD_KEYWORDS):
                        suspicious_methods.append(method_name)
                except Exception:
                    continue
    except Exception as exc:
        logger.debug("Could not read MethodDef table: %s", exc)

    result["total_methods"] = total_methods
    result["suspicious_methods"] = suspicious_methods
    detail("Total methods", str(total_methods))

    if suspicious_methods:
        subheading("Suspicious Methods")
        for m in suspicious_methods:
            warn(f"Suspicious method: {m}")

    # ── MemberRef — external references (P/Invoke etc.) ─────────────────────
    subheading("External References (MemberRef)")
    member_refs: list[str] = []
    try:
        memberref_table = dn.net.mdtables.MemberRef
        if memberref_table:
            for row in memberref_table:
                try:
                    ref_name = str(row.Name) if row.Name else ""
                    # Include P/Invoke-style or native-looking refs
                    if ref_name:
                        member_refs.append(ref_name)
                        info(ref_name)
                except Exception:
                    continue
    except Exception as exc:
        logger.debug("Could not read MemberRef table: %s", exc)

    result["member_refs"] = member_refs
    detail("Total external refs", str(len(member_refs)))

    # ── AssemblyRef ──────────────────────────────────────────────────────────
    subheading("Assembly References")
    assembly_refs: list[dict] = []
    _standard_assemblies = {
        "mscorlib", "System", "System.Core", "System.Data", "System.Web",
        "System.Windows.Forms", "System.Xml", "PresentationFramework",
        "WindowsBase", "System.Drawing", "Microsoft.CSharp",
    }
    try:
        assemblyref_table = dn.net.mdtables.AssemblyRef
        if assemblyref_table:
            for row in assemblyref_table:
                try:
                    name = str(row.Name) if row.Name else "<unknown>"
                    major = getattr(row, "MajorVersion", "?")
                    minor = getattr(row, "MinorVersion", "?")
                    version = f"{major}.{minor}"
                    entry = {"name": name, "version": version}
                    assembly_refs.append(entry)

                    is_standard = any(
                        name == s or name.startswith(s + ".")
                        for s in _standard_assemblies
                    )
                    if is_standard:
                        info(f"{name}  v{version}")
                    else:
                        warn(f"Non-standard assembly: {name}  v{version}")
                except Exception:
                    continue
    except Exception as exc:
        logger.debug("Could not read AssemblyRef table: %s", exc)

    result["assembly_refs"] = assembly_refs
    detail("Assembly references", str(len(assembly_refs)))

    # ── User strings heap ────────────────────────────────────────────────────
    subheading("Interesting User Strings")
    interesting_strings: list[str] = []
    try:
        us = dn.net.user_strings
        if us:
            for s in us:
                try:
                    value = str(s.value) if hasattr(s, "value") else str(s)
                    if not value or value.isspace():
                        continue
                    if any(pat.lower() in value.lower() for pat in _INTERESTING_STRING_PATTERNS):
                        interesting_strings.append(value)
                except Exception:
                    continue
    except Exception as exc:
        logger.debug("Could not read user strings: %s", exc)

    result["user_strings"] = interesting_strings
    if interesting_strings:
        for s in interesting_strings[:40]:
            info(repr(s))
        if len(interesting_strings) > 40:
            info(f"... and {len(interesting_strings) - 40} more")
    else:
        info("No notable user strings found")

    # ── Resources ────────────────────────────────────────────────────────────
    subheading("Embedded Resources")
    try:
        resources = dn.net.resources
        if resources:
            for res in resources:
                try:
                    res_name = str(res.Name) if hasattr(res, "Name") else "<unnamed>"
                    res_data = res.Data if hasattr(res, "Data") else None
                    size = len(res_data) if res_data else 0

                    # Flag suspicious resource content
                    if res_data and len(res_data) >= 2:
                        magic = res_data[:2]
                        if magic == b"MZ":
                            danger(f"Resource '{res_name}' contains embedded PE/executable (MZ header)")
                        elif magic in (b"PK", b"\x1f\x8b"):
                            warn(f"Resource '{res_name}' appears to be a compressed archive")
                        else:
                            info(f"Resource '{res_name}'  ({size} bytes)")
                    else:
                        info(f"Resource '{res_name}'  ({size} bytes)")
                except Exception:
                    continue
            result["resources"] = True
        else:
            info("No embedded resources found")
            result["resources"] = False
    except Exception as exc:
        logger.debug("Could not read resources: %s", exc)
        result["resources"] = False

    return result


def decompile_dotnet(filepath: Path, output_dir: Path | None = None) -> dict:
    """Decompile a .NET assembly to C# using ilspycmd.

    Returns dict with keys: output_path, success.
    """
    if not shutil.which("ilspycmd"):
        info("ilspycmd not installed — skipping .NET decompilation")
        info("Install: dotnet tool install -g ilspycmd")
        return {}

    heading("DOTNET DECOMPILATION")

    out_dir = output_dir or filepath.parent
    decompile_dir = out_dir / f"{filepath.stem}_dotnet_decompiled"

    try:
        result = subprocess.run(
            ["ilspycmd", str(filepath), "-o", str(decompile_dir)],
            capture_output=True,
            text=True,
            timeout=120,
        )

        if result.returncode != 0:
            warn(f"ilspycmd exited with code {result.returncode}")
            if result.stderr:
                warn(result.stderr.strip()[:300])
            return {"output_path": str(decompile_dir), "success": False}

        # Count output files and lines
        cs_files = list(decompile_dir.glob("**/*.cs")) if decompile_dir.exists() else []
        total_lines = 0
        for f in cs_files:
            try:
                total_lines += sum(1 for _ in f.open(encoding="utf-8", errors="replace"))
            except Exception:
                pass

        detail("Output directory", str(decompile_dir))
        detail("Decompiled files", str(len(cs_files)))
        detail("Total lines", str(total_lines))
        info(f"Decompilation complete: {len(cs_files)} .cs file(s), {total_lines} lines")

        return {"output_path": str(decompile_dir), "success": True}

    except subprocess.TimeoutExpired:
        warn("ilspycmd timed out after 120 seconds")
        return {"output_path": str(decompile_dir), "success": False}
    except Exception as exc:
        warn(f"Decompilation failed: {exc}")
        return {"output_path": str(decompile_dir), "success": False}


def run_dotnet_analysis(filepath: Path, pe) -> dict:
    """Main entry point for .NET analysis.

    Silently returns {} if the PE is not a .NET assembly.
    """
    if not is_dotnet_pe(pe):
        return {}

    heading(".NET BINARY DETECTED")
    info("CLR runtime header found — this is a .NET assembly")

    metadata = analyze_dotnet_metadata(filepath)
    decompilation = decompile_dotnet(filepath)

    return {**metadata, "decompilation": decompilation}
