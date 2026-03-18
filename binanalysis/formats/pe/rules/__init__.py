"""PE-specific behavioral rules."""

from binanalysis.formats.pe.rules.generic import PE_GENERIC_RULES
from binanalysis.formats.pe.rules.specimen import SPECIMEN_RULES

PE_RULES = PE_GENERIC_RULES + SPECIMEN_RULES
