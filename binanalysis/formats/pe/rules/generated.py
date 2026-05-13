"""Auto-generated behavioral rules from enrichment pipeline.

Review these rules before committing. Generated from corpus analysis
of 312 samples.
"""

from binanalysis.rules import Rule

GENERATED_RULES: list[Rule] = [
    Rule("gen_adjusttokenprivileges_loadlibraryexw", "privilege_escalation", "high",
         "Auto-generated: AdjustTokenPrivileges + LoadLibraryExW (21.2% of corpus)",
         lambda ctx: ctx.has_all_imports("AdjustTokenPrivileges", "LoadLibraryExW")),
]
