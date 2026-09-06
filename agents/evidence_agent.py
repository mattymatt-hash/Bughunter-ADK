from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4


@dataclass
class Evidence:
    """
    Represents an observation collected during testing.
    """

    id: str

    evidence_type: str
    target: str

    description: str = ""

    source_agent: str = ""

    supports_hypothesis: bool = False

    confidence: float = 0.0

    data: dict[str, Any] = field(default_factory=dict)


class EvidenceAgent:
    """
    Collects, normalizes, and stores evidence produced by other agents.

    Evidence should describe observations rather than making unsupported
    vulnerability claims.
    """

    name = "evidence"

    def __init__(self):
        self.name = "evidence"
        self.evidence: list[Evidence] = []

    def create(
        self,
        evidence_type: str,
        target: str,
        description: str = "",
        source_agent: str = "",
        supports_hypothesis: bool = False,
        confidence: float = 0.0,
        data: dict[str, Any] | None = None,
    ) -> Evidence:
        """
        Create and store an evidence object.
        """

        evidence = Evidence(
            id=str(uuid4()),
            evidence_type=evidence_type,
            target=target,
            description=description,
            source_agent=source_agent,
            supports_hypothesis=supports_hypothesis,
            confidence=max(0.0, min(1.0, confidence)),
            data=data or {},
        )

        self.evidence.append(evidence)

        return evidence

    def add(self, evidence: Evidence) -> Evidence:
        """
        Add an existing Evidence object.
        """

        if evidence.id not in {
            item.id for item in self.evidence
        }:
            self.evidence.append(evidence)

        return evidence

    def get(self, evidence_id: str) -> Evidence | None:
        """
        Retrieve evidence by ID.
        """

        for evidence in self.evidence:
            if evidence.id == evidence_id:
                return evidence

        return None

    def get_for_target(self, target: str) -> list[Evidence]:
        """
        Return all evidence associated with a target.
        """

        return [
            item
            for item in self.evidence
            if item.target == target
        ]

    def get_supporting(
        self,
        target: str | None = None
    ) -> list[Evidence]:
        """
        Return evidence marked as supporting a hypothesis.
        """

        results = [
            item
            for item in self.evidence
            if item.supports_hypothesis
        ]

        if target:
            results = [
                item
                for item in results
                if item.target == target
            ]

        return results

    def run(self, context):
        """
        ManagerAgent-compatible entry point.

        Expected context:

        {
            "evidence_type": "http_response",
            "target": "https://example.com/api/users/123",
            "description": "...",
            "source_agent": "idor",
            "supports_hypothesis": True,
            "confidence": 0.8,
            "data": {...}
        }
        """

        if not isinstance(context, dict):
            return {
                "agent": self.name,
                "status": "error",
                "error": "Context must be a dictionary."
            }

        try:
            evidence = self.create(
                evidence_type=context.get(
                    "evidence_type",
                    "observation"
                ),
                target=context.get(
                    "target",
                    ""
                ),
                description=context.get(
                    "description",
                    ""
                ),
                source_agent=context.get(
                    "source_agent",
                    ""
                ),
                supports_hypothesis=context.get(
                    "supports_hypothesis",
                    False
                ),
                confidence=context.get(
                    "confidence",
                    0.0
                ),
                data=context.get(
                    "data",
                    {}
                ),
            )

            return {
                "agent": self.name,
                "status": "success",
                "evidence": evidence,
            }

        except Exception as e:
            return {
                "agent": self.name,
                "status": "error",
                "error": str(e),
            }