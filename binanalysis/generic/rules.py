"""Generic behavioral rules — format-agnostic, work on any binary.
Only entropy-based and string-based checks belong here."""

from pathlib import Path

from binanalysis.rules import Rule

_DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data"


def _load_benign_domains() -> set[str]:
    path = _DATA_DIR / "benign_domains.txt"
    if not path.exists():
        return set()
    return {line.strip().lower() for line in path.read_text().splitlines()
            if line.strip() and not line.strip().startswith("#")}


_BENIGN_DOMAINS = _load_benign_domains()


def _has_non_benign_urls(ctx) -> bool:
    """Return True only if there are URLs pointing to domains other than known-benign infrastructure."""
    urls = ctx.string_findings.get("url", [])
    if not urls:
        return False
    for item in urls:
        url = item["value"].lower()
        if not any(d in url for d in _BENIGN_DOMAINS):
            return True
    return False


GENERIC_RULES: list[Rule] = [
    Rule("rwx_section", "evasion", "high",
         "Section with both WRITE and EXECUTE permissions",
         lambda ctx: ctx.any_section(
             lambda s: "EXEC" in s.get("characteristics", "") and "WRITE" in s.get("characteristics", ""))),

    Rule("high_entropy_section", "evasion", "medium",
         "Section with entropy > 7.0 (likely packed or encrypted)",
         lambda ctx: ctx.any_section(lambda s: s.get("entropy", 0) > 7.0)),

    Rule("embedded_urls", "network", "medium",
         "Contains embedded URLs (non-infrastructure)",
         _has_non_benign_urls),

    Rule("recon_commands", "discovery", "medium",
         "Contains reconnaissance commands (whoami, systeminfo, etc.)",
         lambda ctx: ctx.has_finding("recon_command")),

    Rule("anti_vm", "evasion", "medium",
         "Virtual machine / sandbox detection strings",
         lambda ctx: any(ctx.has_string_containing(vm) for vm in [
             "VMwareService", "VMwareTray", "VBoxService", "VBoxTray",
             "qemu-ga", "QEMU", "Sandboxie", "SbieDll", "cuckoomon",
             "wine_get_unix_file_name",
         ])),
]
