"""File path context analysis — identify known software from installation paths."""

import re
from pathlib import Path

from binanalysis.output import heading, info, detail

# Maps path patterns (case-insensitive) to known software descriptions.
# Patterns are matched against the full filepath string.
KNOWN_PATHS = [
    # --- Security / DRM ---
    (r"ProgramData[/\\]Sentinel[/\\]AFUCache",
     "Thales Sentinel LDK", "Driver/runtime update cache for Sentinel hardware license dongles (legitimate DRM)"),
    (r"Program Files.*[/\\]SafeNet",
     "SafeNet/Thales", "SafeNet authentication or licensing software"),
    (r"Program Files.*[/\\]Thales",
     "Thales Group", "Thales security/licensing software"),

    # --- Microsoft ---
    (r"ProgramData[/\\]Microsoft[/\\]Windows Defender",
     "Windows Defender", "Microsoft Defender antimalware component"),
    (r"Windows[/\\]System32[/\\]drivers",
     "Windows Kernel Driver", "System driver directory (legitimate if properly signed)"),
    (r"Windows[/\\]SysWOW64",
     "Windows System", "32-bit system binary on 64-bit Windows"),
    (r"Windows[/\\]System32",
     "Windows System", "System binary directory"),
    (r"Program Files.*[/\\]Common Files[/\\]Microsoft Shared",
     "Microsoft Shared", "Microsoft shared component library"),
    (r"Windows[/\\]WinSxS",
     "Windows SxS", "Windows Side-by-Side assembly store"),
    (r"Windows[/\\]Installer",
     "Windows Installer", "Cached MSI installer package"),
    (r"ProgramData[/\\]Package Cache",
     "Visual Studio/VC Redist", "Cached installer from Visual Studio or VC++ Redistributable"),

    # --- Antivirus ---
    (r"Program Files.*[/\\]ESET",
     "ESET", "ESET antivirus/endpoint security component"),
    (r"Program Files.*[/\\]Malwarebytes",
     "Malwarebytes", "Malwarebytes anti-malware component"),
    (r"Program Files.*[/\\]Kaspersky",
     "Kaspersky", "Kaspersky security product component"),
    (r"ProgramData[/\\]Sophos",
     "Sophos", "Sophos endpoint security component"),
    (r"Program Files.*[/\\]CrowdStrike",
     "CrowdStrike", "CrowdStrike Falcon endpoint agent"),
    (r"Program Files.*[/\\]SentinelOne",
     "SentinelOne", "SentinelOne endpoint protection agent"),

    # --- Common software ---
    (r"Program Files.*[/\\]Adobe",
     "Adobe", "Adobe application component"),
    (r"Program Files.*[/\\]Google[/\\]Chrome",
     "Google Chrome", "Chrome browser component"),
    (r"Program Files.*[/\\]Mozilla Firefox",
     "Mozilla Firefox", "Firefox browser component"),
    (r"Program Files.*[/\\]7-Zip",
     "7-Zip", "7-Zip archiver component"),
    (r"Program Files.*[/\\]Python",
     "Python", "Python runtime installation"),
    (r"Program Files.*[/\\]Git",
     "Git", "Git version control installation"),
    (r"Program Files.*[/\\]nodejs",
     "Node.js", "Node.js runtime installation"),
    (r"Program Files.*[/\\]Java",
     "Java", "Java runtime or JDK installation"),

    # --- Suspicious paths ---
    (r"Users[/\\][^/\\]+[/\\]AppData[/\\]Local[/\\]Temp",
     "User Temp Directory", "Binary running from temp directory (common for malware droppers)"),
    (r"\\Recycle",
     "Recycle Bin", "Binary in Recycle Bin (possible hiding technique)"),
]

# Pre-compile patterns
_COMPILED_PATHS = [(re.compile(pat, re.IGNORECASE), name, desc) for pat, name, desc in KNOWN_PATHS]


def analyze_path_context(filepath: Path) -> dict:
    """Check if the binary's file path matches known software locations."""
    heading("FILE PATH CONTEXT")

    result = {}
    path_str = str(filepath)

    for pattern, name, description in _COMPILED_PATHS:
        if pattern.search(path_str):
            result["known_software"] = name
            result["path_description"] = description
            result["matched_path"] = path_str
            info(f"Known software path: {name}")
            detail("Description", description)
            detail("Path", path_str)
            return result

    info("No known software path pattern matched")
    detail("Path", path_str)
    return result
