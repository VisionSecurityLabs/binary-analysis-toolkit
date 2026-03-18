"""Auto-unpacking for UPX-packed PE binaries.

UPX is the most common packer in commodity malware. If `upx` is installed
and the binary is UPX-packed, unpack it and return the path so the analysis
pipeline can work on the unpacked version.
"""

import shutil
import subprocess
import tempfile
from pathlib import Path

from binanalysis.output import heading, info, warn


def try_unpack_upx(filepath: Path) -> Path | None:
    """Try UPX unpacking. Returns path to unpacked file, or None."""
    if not shutil.which("upx"):
        return None

    output_dir = Path(tempfile.mkdtemp(prefix="binanalysis_unpack_"))
    unpacked = output_dir / filepath.name
    shutil.copy2(filepath, unpacked)

    try:
        result = subprocess.run(
            ["upx", "-d", str(unpacked)],
            capture_output=True, text=True, timeout=30,
        )
    except (subprocess.TimeoutExpired, OSError):
        shutil.rmtree(output_dir, ignore_errors=True)
        return None

    if result.returncode != 0:
        shutil.rmtree(output_dir, ignore_errors=True)
        return None

    heading("AUTO-UNPACK")
    info("UPX packing detected and removed")
    info(f"Unpacked binary: {unpacked} ({unpacked.stat().st_size} bytes)")
    return unpacked
