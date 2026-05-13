"""Auto-generated specimen rules — family-specific detections from enrichment pipeline.

Families: WannaCry, Heodo, AmateraStealer, rootkit, Kuping, ACRStealer, signed
Generated from corpus of 863 samples. Review before committing.
"""

from binanalysis.rules import Rule

GENERATED_SPECIMEN_RULES: list[Rule] = [
    Rule("specimen_heodo", "family_detection", "high",
         "Heodo family: distinctive API combo (qsort + bsearch + Process32Next + Process32First)",
         lambda ctx, _a=['qsort', 'bsearch', 'Process32Next', 'Process32First']: all(ctx.has_import(a) for a in _a)),
    # Based on 20 samples

    Rule("specimen_amaterastealer", "family_detection", "high",
         "AmateraStealer family: distinctive APIs (realloc + GetModuleHandleExA + _iob + atoi) + string markers",
         lambda ctx, _a=['realloc', 'GetModuleHandleExA', '_iob', 'atoi'], _s=['ocsp.digicert']:
             all(ctx.has_import(a) for a in _a)
             and any(ctx.has_string_containing(s) for s in _s)),
    # Based on 6 samples

    Rule("specimen_rootkit", "family_detection", "high",
         "rootkit family: distinctive APIs (IoFreeMdl + IoAllocateMdl + MmUnlockPages + MmProbeAndLockPages) + string markers",
         lambda ctx, _a=['IoFreeMdl', 'IoAllocateMdl', 'MmUnlockPages', 'MmProbeAndLockPages'], _s=['com/pki/crl/products/MicrosoftCodeVerifRoot']:
             all(ctx.has_import(a) for a in _a)
             and any(ctx.has_string_containing(s) for s in _s)),
    # Based on 15 samples

    Rule("specimen_kuping", "family_detection", "high",
         "Kuping family: distinctive APIs (KeSetSystemAffinityThread + KeQueryActiveProcessors + NtQuerySystemInformation + KeQueryPerformanceCounter) + string markers",
         lambda ctx, _a=['KeSetSystemAffinityThread', 'KeQueryActiveProcessors', 'NtQuerySystemInformation', 'KeQueryPerformanceCounter'], _s=['com/pki/crl/products/MicrosoftCodeVerifRoot']:
             all(ctx.has_import(a) for a in _a)
             and any(ctx.has_string_containing(s) for s in _s)),
    # Based on 5 samples
]
