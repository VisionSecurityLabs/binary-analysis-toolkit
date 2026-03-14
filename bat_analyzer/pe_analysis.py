"""Structural PE analysis — headers, sections, imports, exports, resources, TLS, compiler, strings."""

import re
import hashlib
import math
import datetime
from pathlib import Path

import pefile

from bat_analyzer.config import SUSPICIOUS_IMPORTS, SUSPICIOUS_STRING_PATTERNS
from bat_analyzer.output import C, heading, subheading, info, warn, danger, detail
from bat_analyzer.strings import extract_ascii_strings, extract_wide_strings

import re as _re

# Pre-compile string patterns for performance
_COMPILED_PATTERNS = [
    (_re.compile(p.regex, _re.IGNORECASE), p)
    for p in SUSPICIOUS_STRING_PATTERNS
]


def analyze_hashes(filepath: Path, data: bytes) -> dict:
    heading("FILE HASHES")
    hashes = {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    detail("MD5", hashes["md5"])
    detail("SHA1", hashes["sha1"])
    detail("SHA256", hashes["sha256"])
    detail("File Size", f"{len(data)} bytes ({len(data)/1024:.1f} KB)")
    detail("File Name", filepath.name)
    return hashes


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
        dll = entry.dll.decode('utf-8', errors='replace')
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


def analyze_imphash(pe: pefile.PE) -> dict:
    heading("IMPORT HASH & FUZZY HASHES")
    imphash = pe.get_imphash()
    detail("Imphash", imphash)
    return {"imphash": imphash}


def analyze_rich_header(pe: pefile.PE) -> dict:
    heading("RICH HEADER ANALYSIS")

    if pe.RICH_HEADER is None:
        info("No Rich header (non-MSVC compiler)")
        return {}

    known_products = {
        1: "Import0", 2: "Linker510", 3: "Cvtomf510", 4: "Linker600",
        5: "Cvtomf600", 6: "Cvtres500", 7: "Utc11_Basic", 8: "Utc11_C",
        9: "Utc12_Basic", 10: "Utc12_C", 11: "Utc12_CPP",
        15: "Linker620", 16: "Cvtomf620",
        19: "Linker700", 21: "Linker710p",
        40: "Utc1310_C", 41: "Utc1310_CPP",
        45: "Linker710", 83: "Linker800",
        95: "Utc1400_C", 96: "Utc1400_CPP",
        104: "Linker900", 105: "Masm900",
        154: "Utc1500_C", 155: "Utc1500_CPP",
        170: "Linker1000", 171: "Masm1000",
        199: "Utc1600_C", 200: "Utc1600_CPP",
        214: "Linker1100",
        258: "Utc1700_C", 259: "Utc1700_CPP",
        260: "Linker1200",
        261: "Utc1810_C", 262: "Utc1810_CPP",
        263: "Linker1400",
        264: "Utc1900_C", 265: "Utc1900_CPP",
    }

    rich_header_data = pe.parse_rich_header()
    entries = []
    if rich_header_data and "values" in rich_header_data:
        print(f"  {'Product':20s} {'Build':>8s} {'Count':>8s}")
        print(f"  {'─' * 40}")
        for comp_id, count in rich_header_data["values"]:
            prodid = comp_id >> 16
            build = comp_id & 0xFFFF
            name = known_products.get(prodid, f"Unknown_{prodid}")
            print(f"  {name:20s} {build:>8d} {count:>8d}")
            entries.append({
                "product_id": prodid,
                "product_name": name,
                "build": build,
                "count": count,
            })

    rich_hash = hashlib.md5(pe.RICH_HEADER.clear_data).hexdigest()
    detail("Rich Header Hash (MD5)", rich_hash)

    if all(b == 0 for b in pe.RICH_HEADER.clear_data):
        warn("Rich header clear_data is all zeros — possible forgery")
    if len(entries) == 1:
        warn("Only 1 Rich header entry — possible forgery")

    return {"rich_hash": rich_hash, "entries": entries}


def analyze_overlay(data: bytes, pe: pefile.PE) -> dict:
    heading("OVERLAY / APPENDED DATA")

    overlay_offset = pe.get_overlay_data_start_offset()
    if overlay_offset is None or overlay_offset >= len(data):
        info("No overlay data")
        return {}

    overlay_size = len(data) - overlay_offset
    overlay_data = data[overlay_offset:]
    overlay_preview = overlay_data[:256]

    overlay_sha256 = hashlib.sha256(overlay_data).hexdigest()

    prob = [float(overlay_data.count(bytes([b]))) / len(overlay_data) for b in set(overlay_data)]
    entropy = -sum(p * math.log2(p) for p in prob if p > 0)

    detail("Overlay Offset", hex(overlay_offset))
    detail("Overlay Size", f"{overlay_size} bytes ({overlay_size / 1024:.1f} KB)")
    detail("SHA256", overlay_sha256)
    detail("Entropy", f"{entropy:.4f}")

    type_hint = "unknown"
    if overlay_preview[:2] == b'MZ':
        type_hint = "PE executable"
        danger("Overlay contains embedded PE executable!")
    elif overlay_preview[:2] == b'PK':
        type_hint = "ZIP archive"
        warn("Overlay contains ZIP archive")
    elif overlay_preview[:3] == b'Rar' or overlay_preview[:3] == b'\x52\x61\x72':
        type_hint = "RAR archive"
        warn("Overlay contains RAR archive")

    if entropy > 7.0:
        warn("Overlay has high entropy — likely encrypted or compressed")
    if overlay_size > len(data) * 0.5:
        warn(f"Overlay is {overlay_size * 100 // len(data)}% of total file — suspicious")

    return {
        "offset": hex(overlay_offset),
        "size": overlay_size,
        "sha256": overlay_sha256,
        "entropy": round(entropy, 4),
        "type_hint": type_hint,
    }


def analyze_strings(data: bytes,
                     ascii_strings: list[tuple[int, str]] | None = None,
                     wide_strings: list[tuple[int, str]] | None = None) -> dict:
    heading("STRING ANALYSIS")

    if ascii_strings is None:
        ascii_strings = extract_ascii_strings(data, min_len=4)
    if wide_strings is None:
        wide_strings = extract_wide_strings(data, min_len=4)

    # Deobfuscate before matching
    from bat_analyzer.deobfuscate import deobfuscate_strings
    deobfuscated_ascii = deobfuscate_strings(ascii_strings)
    deobfuscated_wide = deobfuscate_strings(wide_strings)

    all_strings = [(off, s, "ascii") for off, s in ascii_strings]
    all_strings += [(off, s, "wide") for off, s in wide_strings]
    all_strings += [(off, s, "decoded") for off, s in deobfuscated_ascii]
    all_strings += [(off, s, "decoded") for off, s in deobfuscated_wide]

    findings = {}

    for offset, string, encoding in all_strings:
        for compiled_re, pat in _COMPILED_PATTERNS:
            for m in compiled_re.finditer(string):
                match_str = m.group()
                findings.setdefault(pat.category, []).append({
                    "value": match_str,
                    "offset": offset,
                    "encoding": encoding,
                    "full_string": string[:200],
                    "weight": pat.weight,
                })

    # Deduplicate by value within each category
    for cat in findings:
        seen = set()
        deduped = []
        for item in findings[cat]:
            if item["value"] not in seen:
                seen.add(item["value"])
                deduped.append(item)
        findings[cat] = deduped

    # Validate bitcoin addresses to reduce false positives
    from bat_analyzer.validators import is_valid_bitcoin_address
    if "bitcoin_address" in findings:
        findings["bitcoin_address"] = [
            item for item in findings["bitcoin_address"]
            if is_valid_bitcoin_address(item["value"])
        ]
        if not findings["bitcoin_address"]:
            del findings["bitcoin_address"]

    # False positive suppression: remove categories that require other signals
    requires_map = {
        pat.category: pat.requires
        for pat in SUSPICIOUS_STRING_PATTERNS
        if pat.requires
    }
    for cat, required_cats in requires_map.items():
        if cat in findings and not any(findings.get(r) for r in required_cats):
            del findings[cat]

    category_labels = {
        "url": "URLs",
        "domain": "Domains / Hostnames",
        "github_pat": "GitHub Personal Access Tokens",
        "github_token": "GitHub Tokens",
        "bearer_token": "Bearer Tokens",
        "auth_header": "Authorization Headers",
        "github_api": "GitHub API References",
        "github_repo_path": "GitHub Repo Paths",
        "github_contents_path": "GitHub Contents Paths",
        "user_agent": "User-Agent Strings",
        "content_type_header": "Content-Type Headers",
        "accept_header": "Accept Headers",
        "ms_oauth": "Microsoft OAuth Endpoints",
        "oauth_endpoint": "OAuth Endpoints",
        "sso_nonce": "SSO Nonce References",
        "client_id": "Client IDs",
        "redirect_uri": "Redirect URIs",
        "uuid": "UUIDs / GUIDs",
        "windows_path": "Windows File Paths",
        "env_variable": "Environment Variables",
        "registry_key": "Registry Keys",
        "json_object": "JSON Structures",
        "json_message_key": "JSON 'message' Keys",
        "json_content_key": "JSON 'content' Keys",
        "json_branch_key": "JSON 'branch' Keys",
        "recon_command": "Reconnaissance Commands",
        "possible_base64": "Possible Base64 Blobs",
    }

    skip_display = {"possible_base64"}

    for cat, items in sorted(findings.items()):
        if cat in skip_display:
            continue
        label = category_labels.get(cat, cat)
        subheading(label)
        for item in items[:20]:
            enc_tag = f" [{item['encoding']}]" if item['encoding'] == 'wide' else ""
            if cat in ("github_pat", "github_token", "bearer_token"):
                danger(f"{item['value']}{enc_tag}")
            elif cat in ("url", "ms_oauth", "github_api", "windows_path"):
                warn(f"{item['value']}{enc_tag}")
            else:
                info(f"{item['value']}{enc_tag}")

    return findings


def analyze_dynamic_apis(data: bytes) -> list[str]:
    heading("DYNAMICALLY RESOLVED APIs")

    suspicious_keywords = [
        "Create", "Open", "Write", "Read", "Virtual", "Alloc", "Process",
        "Thread", "Token", "Registry", "Shell", "Internet", "Http", "Socket",
        "Inject", "Hook", "Crypt", "Download", "Upload", "Execute", "Startup",
        "Service", "Pipe", "LoadLibrary", "GetProc",
    ]

    api_names = set()
    for m in re.finditer(rb'([A-Z][a-zA-Z0-9]{5,50}(?:W|A)?)\x00', data):
        name = m.group(1).decode('ascii', errors='ignore')
        if any(kw in name for kw in suspicious_keywords):
            api_names.add(name)

    if api_names:
        for name in sorted(api_names):
            warn(f"{name}")
    else:
        info("No dynamically resolved suspicious APIs detected")

    return sorted(api_names)


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
