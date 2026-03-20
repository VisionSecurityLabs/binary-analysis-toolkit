"""PE-specific behavioral rules."""

from binanalysis.formats.pe.rules.generic import PE_GENERIC_RULES
from binanalysis.formats.pe.rules.specimen import SPECIMEN_RULES

PE_RULES = PE_GENERIC_RULES + SPECIMEN_RULES

try:
    from binanalysis.formats.pe.rules.generated import GENERATED_RULES
    PE_RULES = PE_RULES + GENERATED_RULES
except ImportError:
    pass

try:
    from binanalysis.formats.pe.rules.generated_specimen import GENERATED_SPECIMEN_RULES
    PE_RULES = PE_RULES + GENERATED_SPECIMEN_RULES
except ImportError:
    pass
