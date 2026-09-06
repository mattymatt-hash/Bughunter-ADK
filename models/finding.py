from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    """
    Represents a validated security finding.

    A Finding should only be created after the evidence has been
    reviewed/validated.
    """

    id: str
    vulnerability_type: str
    title: str
    target: str

    description: str = ""

    severity: str = "info"

    confidence: float = 0.0

    status: str = "confirmed"

    agent: str = ""

    evidence_ids: list[str] = field(default_factory=list)

    impact: str = ""
    remediation: str = ""

    metadata: dict[str, Any] = field(default_factory=dict)

    def add_evidence(self, evidence_id: str):
        """
        Associate evidence with this finding.
        """
        if evidence_id not in self.evidence_ids:
            self.evidence_ids.append(evidence_id)

    def is_valid(self) -> bool:
        """
        A finding should have at least one piece of evidence.
        """
        return len(self.evidence_ids) > 0

    def set_severity(self, severity: str):
        """
        Update finding severity.
        """
        allowed = {
            "info",
            "low",
            "medium",
            "high",
            "critical",
        }

        severity = severity.lower()

        if severity not in allowed:
            raise ValueError(
                f"Invalid severity '{severity}'. "
                f"Allowed values: {sorted(allowed)}"
            )

        self.severity = severity