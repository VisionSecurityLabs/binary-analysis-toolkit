"""Installer framework detection — NSIS, Inno Setup, InstallShield, WiX, WISE."""

import pefile

from binanalysis.output import heading, info, detail


def detect_installer(data: bytes, pe: pefile.PE) -> dict:
    """Detect known installer frameworks from overlay data, resources, and markers."""
    heading("INSTALLER / FRAMEWORK DETECTION")

    result = {}

    # --- NSIS (Nullsoft Installer System) ---
    # NSIS appends a NullsoftInst marker and uses 0xDEADBEEF magic in overlay
    if b"NullsoftInst" in data or b"Nullsoft.NSIS" in data:
        result["framework"] = "NSIS"
        result["framework_full"] = "Nullsoft Scriptable Install System"
        # Try to extract version from manifest string like "Nullsoft Install System v3.08"
        import re
        match = re.search(rb"Nullsoft Install System (v[\d.]+)", data)
        if match:
            result["framework_version"] = match.group(1).decode("ascii", errors="replace")
    # NSIS magic in overlay: EF BE AD DE
    elif _has_overlay(pe):
        overlay_offset = _overlay_offset(pe)
        if overlay_offset and overlay_offset < len(data):
            overlay = data[overlay_offset:overlay_offset + 512]
            if b"\xef\xbe\xad\xde" in overlay:
                result["framework"] = "NSIS"
                result["framework_full"] = "Nullsoft Scriptable Install System"

    # --- Inno Setup ---
    if not result and b"Inno Setup" in data:
        result["framework"] = "Inno Setup"
        result["framework_full"] = "Inno Setup Installer"
        for line in data.split(b"\x00"):
            if b"Inno Setup Setup Data" in line:
                try:
                    ver_str = line.decode("utf-8", errors="replace")
                    # Format: "Inno Setup Setup Data (X.Y.Z)"
                    if "(" in ver_str and ")" in ver_str:
                        result["framework_version"] = ver_str[ver_str.index("(") + 1:ver_str.index(")")]
                except Exception:
                    pass
                break

    # --- InstallShield ---
    if not result:
        if b"InstallShield" in data or b"ISSetupStream" in data:
            result["framework"] = "InstallShield"
            result["framework_full"] = "InstallShield Installer"

    # --- WiX / MSI stub ---
    if not result:
        if b"Windows Installer" in data and (b"msi" in data.lower() or b"WiX" in data):
            result["framework"] = "WiX/MSI"
            result["framework_full"] = "Windows Installer (MSI)"

    # --- WISE Installer ---
    if not result:
        if b"WISE" in data and b"WiseMain" in data:
            result["framework"] = "WISE"
            result["framework_full"] = "WISE Installation System"

    # --- 7-Zip SFX ---
    if not result:
        if b"7z\xbc\xaf\x27\x1c" in data and _has_overlay(pe):
            result["framework"] = "7-Zip SFX"
            result["framework_full"] = "7-Zip Self-Extracting Archive"

    # --- WinRAR SFX ---
    if not result:
        if b"SFX module" in data and b"WinRAR" in data:
            result["framework"] = "WinRAR SFX"
            result["framework_full"] = "WinRAR Self-Extracting Archive"

    if result:
        result["is_installer"] = True
        info(f"Detected: {result['framework_full']}")
        detail("Framework", result["framework"])
        if "framework_version" in result:
            detail("Version", result["framework_version"])
    else:
        result["is_installer"] = False
        info("No known installer framework detected")

    return result


def _has_overlay(pe: pefile.PE) -> bool:
    """Check if PE has data appended after the last section."""
    return _overlay_offset(pe) is not None


def _overlay_offset(pe: pefile.PE) -> int | None:
    """Return the file offset where overlay data begins, or None."""
    if not pe.sections:
        return None
    last = max(pe.sections, key=lambda s: s.PointerToRawData)
    end = last.PointerToRawData + last.SizeOfRawData
    if end < len(pe.__data__):
        return end
    return None
