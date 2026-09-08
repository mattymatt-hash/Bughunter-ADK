from enum import Enum


class ValidationStatus(str, Enum):
    NOT_TESTED = "not_tested"
    OBSERVED = "observed"
    VALIDATION_READY = "validation_ready"
    VALIDATED = "validated"
    REJECTED = "rejected"
    INCONCLUSIVE = "inconclusive"