from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class AgentResult:
    """
    Standard result returned by every BugHunter security agent.
    """

    agent: str
    target: str
    status: str = "completed"

    hypotheses: list[Any] = field(default_factory=list)
    evidence: list[Any] = field(default_factory=list)
    observations: list[Any] = field(default_factory=list)
    findings: list[Any] = field(default_factory=list)

    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def success(self) -> bool:
        return self.status in {"completed", "partial"}

    def add_hypothesis(self, hypothesis: Any) -> None:
        self.hypotheses.append(hypothesis)

    def add_evidence(self, evidence: Any) -> None:
        self.evidence.append(evidence)

    def add_observation(self, observation: Any) -> None:
        self.observations.append(observation)

    def add_finding(self, finding: Any) -> None:
        self.findings.append(finding)

    def add_error(self, error: str) -> None:
        self.errors.append(str(error))
        if self.status == "completed":
            self.status = "partial"
