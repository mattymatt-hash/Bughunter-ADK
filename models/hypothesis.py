from dataclasses import dataclass, field
from typing import Any


@dataclass
class Hypothesis:
    """
    Represents a security hypothesis that an agent wants to investigate.

    A hypothesis is NOT a confirmed vulnerability.
    It represents something that should be tested and validated.
    """

    id: str
    agent: str
    vulnerability_type: str
    target: str

    description: str = ""

    confidence: float = 0.0
    priority: str = "medium"

    status: str = "pending"

    evidence_ids: list[str] = field(default_factory=list)

    metadata: dict[str, Any] = field(default_factory=dict)

    def add_evidence(self, evidence_id: str):
        """
        Associate evidence with this hypothesis.
        """
        if evidence_id not in self.evidence_ids:
            self.evidence_ids.append(evidence_id)

    def mark_testing(self):
        """
        Mark the hypothesis as currently being tested.
        """
        self.status = "testing"

    def mark_supported(self):
        """
        Mark the hypothesis as supported by evidence.
        """
        self.status = "supported"

    def mark_rejected(self):
        """
        Mark the hypothesis as rejected.
        """
        self.status = "rejected"

    def mark_inconclusive(self):
        """
        Mark the hypothesis as inconclusive.
        """
        self.status = "inconclusive"