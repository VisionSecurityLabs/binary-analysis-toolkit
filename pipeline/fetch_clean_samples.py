"""
Download known-clean PE files for false positive validation.

Sources:
  - SysInternals (Microsoft) — signed standalone utilities
  - NirSoft — small signed PE tools

Usage:
    uv run python pipeline/fetch_clean_samples.py
    uv run python pipeline/fetch_clean_samples.py --out clean_samples/
"""

from __future__ import annotations

import argparse
from pathlib import Path

import requests

DEFAULT_OUT = Path("clean_samples")

# SysInternals live download (Microsoft-signed, stable URLs)
SYSINTERNALS = [
    "https://live.sysinternals.com/procmon.exe",
    "https://live.sysinternals.com/autoruns.exe",
    "https://live.sysinternals.com/tcpview.exe",
    "https://live.sysinternals.com/pslist.exe",
    "https://live.sysinternals.com/listdlls.exe",
    "https://live.sysinternals.com/handle.exe",
    "https://live.sysinternals.com/Procexp.exe",
    "https://live.sysinternals.com/sigcheck.exe",
    "https://live.sysinternals.com/strings.exe",
    "https://live.sysinternals.com/whois.exe",
    "https://live.sysinternals.com/accesschk.exe",
    "https://live.sysinternals.com/du.exe",
    "https://live.sysinternals.com/logonsessions.exe",
    "https://live.sysinternals.com/pipelist.exe",
    "https://live.sysinternals.com/psinfo.exe",
]

# NirSoft tools (unsigned but well-known clean utilities)
NIRSOFT = [
    "https://www.nirsoft.net/utils/dnsquerysniffer.zip",
    "https://www.nirsoft.net/utils/cports.zip",
]

# Additional well-known tools (broadens FP coverage)
ADDITIONAL_TOOLS = [
    "https://www.7-zip.org/a/7z2408-x64.exe",
    "https://www.python.org/ftp/python/3.12.0/python-3.12.0-embed-amd64.zip",
]

# .NET framework assemblies (copied from local system if available)
DOTNET_ASSEMBLIES = [
    Path(r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\mscorlib.dll"),
    Path(r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\System.dll"),
    Path(r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\System.Core.dll"),
    Path(r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\System.Net.dll"),
]


def download_file(url: str, out_dir: Path) -> bool:
    name = url.rsplit("/", 1)[-1]
    out_path = out_dir / name
    if out_path.exists():
        print(f"  [=] {name} (already exists)")
        return True

    try:
        resp = requests.get(url, timeout=30, headers={"User-Agent": "binanalysis-toolkit"})
        resp.raise_for_status()
        out_path.write_bytes(resp.content)
        size_kb = len(resp.content) / 1024
        print(f"  [+] {name} ({size_kb:.0f} KB)")
        return True
    except Exception as e:
        print(f"  [!] {name} — failed: {e}")
        return False


def extract_zips(out_dir: Path) -> None:
    import zipfile
    for zf_path in list(out_dir.glob("*.zip")):
        try:
            with zipfile.ZipFile(zf_path) as zf:
                for member in zf.namelist():
                    if member.lower().endswith((".exe", ".dll")):
                        target = out_dir / Path(member).name
                        if not target.exists():
                            target.write_bytes(zf.read(member))
                            print(f"  [+] extracted {target.name}")
            zf_path.unlink()
        except Exception as e:
            print(f"  [!] Failed to extract {zf_path.name}: {e}")


def copy_system_assemblies(out_dir: Path) -> None:
    """Copy .NET framework DLLs from the local system if available."""
    import shutil
    copied = 0
    for src in DOTNET_ASSEMBLIES:
        if src.exists():
            dst = out_dir / src.name
            if not dst.exists():
                shutil.copy2(src, dst)
                print(f"  [+] {src.name} (system copy)")
                copied += 1
            else:
                print(f"  [=] {src.name} (already exists)")
    if not copied:
        print("  [*] No .NET assemblies found on this system (expected on non-Windows)")


def main():
    parser = argparse.ArgumentParser(description="Download known-clean PEs for validation")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT,
                        help=f"Output directory (default: {DEFAULT_OUT})")
    parser.add_argument("--include-system", action="store_true",
                        help="Copy .NET framework DLLs from the local system")
    args = parser.parse_args()

    args.out.mkdir(parents=True, exist_ok=True)

    print(f"[*] Downloading SysInternals tools ({len(SYSINTERNALS)} files)")
    for url in SYSINTERNALS:
        download_file(url, args.out)

    print(f"\n[*] Downloading NirSoft tools ({len(NIRSOFT)} files)")
    for url in NIRSOFT:
        download_file(url, args.out)

    print(f"\n[*] Downloading additional tools ({len(ADDITIONAL_TOOLS)} files)")
    for url in ADDITIONAL_TOOLS:
        download_file(url, args.out)

    print(f"\n[*] Extracting ZIP archives")
    extract_zips(args.out)

    if args.include_system:
        print(f"\n[*] Copying .NET framework assemblies")
        copy_system_assemblies(args.out)

    total = len(list(args.out.glob("*.exe")) + list(args.out.glob("*.dll")))
    print(f"\n[*] Done — {total} clean PE files in {args.out}/")


if __name__ == "__main__":
    main()
