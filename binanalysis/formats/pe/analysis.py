"""Structural PE analysis — headers, sections, imports, exports, resources, TLS, compiler."""

import datetime

import pefile

from binanalysis.formats.pe.config import SUSPICIOUS_IMPORTS
from binanalysis.output import C, heading, subheading, info, warn, danger, detail
from binanalysis.strings import extract_ascii_strings, extract_wide_strings


def analyze_pe_headers(pe: pefile.PE) -> dict:
    heading("PE HEADER ANALYSIS")

    machine_types = {0x14c: "i386", 0x8664: "AMD64", 0x1c0: "ARM", 0xaa64: "ARM64"}
    subsystems = {
        1: "Native", 2: "Windows GUI", 3: "Windows Console",
        7: "POSIX", 9: "WinCE", 14: "EFI Application",
    }

    machine = pe.FILE_HEADER.Machine
    ts = pe.FILE_HEADER.TimeDateStamp
    compile_time = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)

    result = {
        "machine": machine_types.get(machine, hex(machine)),
        "compile_time": str(compile_time),
        "compile_timestamp_hex": hex(ts),
        "subsystem": subsystems.get(pe.OPTIONAL_HEADER.Subsystem, "Unknown"),
        "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
        "num_sections": pe.FILE_HEADER.NumberOfSections,
    }

    subheading("Basic Info")
    detail("Architecture", result["machine"])
    detail("Subsystem", result["subsystem"])
    detail("Compile Time", f"{compile_time} UTC ({hex(ts)})")
    detail("Entry Point", result["entry_point"])
    detail("Image Base", result["image_base"])
    detail("Sections", str(result["num_sections"]))

    now = datetime.datetime.now(tz=datetime.timezone.utc)
    if compile_time > now:
        warn("Compile time is in the FUTURE — likely forged")
    elif (now - compile_time).days < 7:
        warn(f"Compiled very recently ({(now - compile_time).days} days ago)")
    elif compile_time.year < 2000:
        warn("Compile time suspiciously old — likely forged")

    subheading("Security Features")
    dll_chars = pe.OPTIONAL_HEADER.DllCharacteristics
    aslr = bool(dll_chars & 0x40)
    dep = bool(dll_chars & 0x100)
    no_seh = bool(dll_chars & 0x400)
    cfg = bool(dll_chars & 0x4000)
    detail("ASLR", f"{'Enabled' if aslr else 'DISABLED'}")
    detail("DEP/NX", f"{'Enabled' if dep else 'DISABLED'}")
    detail("No SEH", f"{'Yes' if no_seh else 'No'}")
    detail("Control Flow Guard", f"{'Enabled' if cfg else 'Disabled'}")

    return result


def analyze_sections(pe: pefile.PE) -> list[dict]:
    heading("SECTIONS")

    sections = []
    print(f"  {'Name':10s} {'VirtAddr':>12s} {'VirtSize':>10s} {'RawSize':>10s} {'Entropy':>8s}  Flags")
    print(f"  {'─' * 70}")

    for s in pe.sections:
        name = s.Name.decode('utf-8', errors='replace').rstrip('\x00')
        entropy = s.get_entropy()
        chars = []
        if s.Characteristics & 0x20000000:
            chars.append("EXEC")
        if s.Characteristics & 0x40000000:
            chars.append("READ")
        if s.Characteristics & 0x80000000:
            chars.append("WRITE")

        flags_str = "|".join(chars)
        ent_color = C.RESET
        ent_note = ""
        if entropy > 7.0:
            ent_color = C.RED
            ent_note = " PACKED/ENCRYPTED"
        elif entropy > 6.5:
            ent_color = C.YELLOW
            ent_note = " elevated"

        sec_info = {
            "name": name,
            "virtual_address": hex(s.VirtualAddress),
            "virtual_size": hex(s.Misc_VirtualSize),
            "raw_size": hex(s.SizeOfRawData),
            "entropy": round(entropy, 2),
            "characteristics": flags_str,
        }
        sections.append(sec_info)

        print(f"  {name:10s} {hex(s.VirtualAddress):>12s} {hex(s.Misc_VirtualSize):>10s} "
              f"{hex(s.SizeOfRawData):>10s} {ent_color}{entropy:>7.2f}{ent_note}{C.RESET}  {flags_str}")

        if s.SizeOfRawData == 0 and s.Misc_VirtualSize > 0:
            warn(f"  Section '{name}' has zero raw size but non-zero virtual size")
        if s.Characteristics & 0x20000000 and s.Characteristics & 0x80000000:
            warn(f"  Section '{name}' is both WRITABLE and EXECUTABLE")

    return sections


def analyze_imports(pe: pefile.PE) -> dict:
    heading("IMPORTS ANALYSIS")

    imports = {}
    suspicious_found = {}

    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        info("No import table found (possible packing)")
        return imports

    all_suspicious = {}
    for category, apis in SUSPICIOUS_IMPORTS.items():
        for api in apis:
            all_suspicious[api.lower()] = category

    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        if not entry.dll:
            continue
        dll = entry.dll.decode('utf-8', errors='replace').strip('\x00')
        if not dll or not any(dll.lower().endswith(ext) for ext in ('.dll', '.exe', '.sys', '.drv', '.ocx')):
            continue
        funcs = []
        for imp in entry.imports:
            name = imp.name.decode('utf-8', errors='replace') if imp.name else f"ord({imp.ordinal})"
            funcs.append(name)
            stripped = name.removesuffix('A') if name.endswith('A') else name.removesuffix('W')
            cat = all_suspicious.get(name.lower()) or all_suspicious.get(stripped.lower())
            if cat:
                suspicious_found.setdefault(cat, []).append(f"{dll}!{name}")

        imports[dll] = funcs
        print(f"  {C.BOLD}{dll}{C.RESET} ({len(funcs)} functions)")

    if suspicious_found:
        subheading("Suspicious API Usage")
        for category, apis in sorted(suspicious_found.items()):
            danger(f"{category.upper()}:")
            for api in apis:
                print(f"      → {api}")

    return imports


def analyze_exports(pe: pefile.PE) -> list[str]:
    heading("EXPORTS")
    exports = []
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name = exp.name.decode() if exp.name else f"ord({exp.ordinal})"
            exports.append(name)
            detail(name, hex(exp.address))
    else:
        info("No exports (typical for EXE)")
    return exports


def analyze_resources(pe: pefile.PE) -> dict:
    heading("RESOURCES")

    resource_types = {
        1: "RT_CURSOR", 2: "RT_BITMAP", 3: "RT_ICON", 4: "RT_MENU",
        5: "RT_DIALOG", 6: "RT_STRING", 9: "RT_ACCELERATOR",
        10: "RT_RCDATA", 14: "RT_GROUP_ICON", 16: "RT_VERSION",
        24: "RT_MANIFEST",
    }

    resources = {}
    if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        info("No resources found")
        return resources

    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        rtype = resource_types.get(entry.id, f"Type_{entry.id}")
        rname = str(entry.name) if entry.name else rtype
        resources[rname] = {"type_id": entry.id, "type_name": rtype}
        info(f"{rtype} (id={entry.id})")

    return resources


def analyze_version_info(pe: pefile.PE) -> dict:
    heading("VERSION INFO (METADATA)")

    version = {}
    if hasattr(pe, 'FileInfo'):
        for fi_list in pe.FileInfo:
            for entry in fi_list:
                if hasattr(entry, 'StringTable'):
                    for st in entry.StringTable:
                        for k, v in st.entries.items():
                            key = k.decode('utf-8', errors='replace')
                            val = v.decode('utf-8', errors='replace')
                            version[key] = val
                            detail(key, val)

    if not version:
        info("No version info found")

    return version


def analyze_tls(pe: pefile.PE) -> dict:
    heading("TLS CALLBACKS")

    tls = {}
    if hasattr(pe, 'DIRECTORY_ENTRY_TLS') and pe.DIRECTORY_ENTRY_TLS:
        addr = pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks
        tls["callback_address"] = hex(addr)
        warn(f"TLS callback table at {hex(addr)} — may execute code before entry point")
    else:
        info("No TLS callbacks")

    return tls


def analyze_compiler(data: bytes, pe: pefile.PE,
                     ascii_strs: set[str] | None = None,
                     wide_strs: set[str] | None = None) -> dict:
    heading("COMPILER / TOOLCHAIN")

    compiler_info = {}

    if ascii_strs is None:
        ascii_strs = {s for _, s in extract_ascii_strings(data, 6)}
    if wide_strs is None:
        wide_strs = {s for _, s in extract_wide_strings(data, 4)}

    if any("Mingw" in s or "mingw" in s for s in ascii_strs):
        compiler_info["compiler"] = "MinGW-w64 (GCC cross-compiler)"
        warn("MinGW-w64 — commonly used to cross-compile Windows malware from Linux")
    elif any("MSVC" in s for s in ascii_strs) or b"Rich" in data[:0x200]:
        compiler_info["compiler"] = "MSVC (Visual Studio)"
    elif any("Borland" in s for s in ascii_strs):
        compiler_info["compiler"] = "Borland/Embarcadero"
    elif any("Go build" in s or "runtime.go" in s for s in ascii_strs):
        compiler_info["compiler"] = "Go"

    if any("gcc.gnu.org" in s for s in ascii_strs):
        compiler_info["gcc_references"] = True
        info("References to gcc.gnu.org found — GCC-compiled")

    all_strs = ascii_strs | wide_strs

    languages = set()
    if any("ERREUR" in s for s in all_strs):
        languages.add("French")
    if any("Fehler" in s for s in all_strs):
        languages.add("German")
    if any("ошибка" in s.lower() for s in all_strs):
        languages.add("Russian")

    if languages:
        compiler_info["developer_languages"] = list(languages)
        for lang in languages:
            warn(f"Developer language hint: {lang}")

    if compiler_info.get("compiler"):
        detail("Compiler", compiler_info["compiler"])

    return compiler_info
