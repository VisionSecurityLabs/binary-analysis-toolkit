"""Generic behavioral rules — format-agnostic, work on any binary.
Only entropy-based and string-based checks belong here."""

from binanalysis.rules import Rule

GENERIC_RULES: list[Rule] = [
    Rule("rwx_section", "evasion", "high",
         "Section with both WRITE and EXECUTE permissions",
         lambda ctx: ctx.any_section(
             lambda s: "EXEC" in s.get("characteristics", "") and "WRITE" in s.get("characteristics", ""))),

    Rule("high_entropy_section", "evasion", "medium",
         "Section with entropy > 7.0 (likely packed or encrypted)",
         lambda ctx: ctx.any_section(lambda s: s.get("entropy", 0) > 7.0)),

    Rule("embedded_urls", "network", "medium",
         "Contains embedded URLs",
         lambda ctx: ctx.has_finding("url")),

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
