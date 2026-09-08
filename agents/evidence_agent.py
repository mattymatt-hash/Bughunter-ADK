from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

from models.security_rating import (
    clamp_confidence,
    normalize_severity,
)


@dataclass
class Evidence:
    """
    Represents traceable evidence produced from an agent observation.

    Evidence is non-confirmatory by default. Only controlled validation
    should mark evidence as supporting a hypothesis.
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
    Collects, normalizes, and stores evidence produced by security agents.

    Observations can be converted into evidence while preserving their
    source URL, severity, confidence, and original observation data.

    Evidence does not automatically become a vulnerability finding.
    ValidatorAgent is responsible for determining whether evidence
    actually supports a hypothesis.
    """

    name = "evidence"

    def __init__(self) -> None:
        self.name = "evidence"

        # UUID -> Evidence
        self.evidence: dict[str, Evidence] = {}

    # ------------------------------------------------------------------
    # Evidence creation
    # ------------------------------------------------------------------

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
        Create and store an Evidence object.
        """

        normalized_data = dict(data or {})

        # Preserve source URL when available.
        if "source_url" not in normalized_data:
            normalized_data["source_url"] = (
                target if target else None
            )

        # Normalize severity if supplied.
        if "severity" in normalized_data:
            normalized_data["severity"] = normalize_severity(
                normalized_data["severity"]
            )

        # Normalize confidence inside the evidence payload too.
        normalized_data["confidence"] = clamp_confidence(
            normalized_data.get(
                "confidence",
                confidence,
            )
        )

        evidence = Evidence(
            id=str(uuid4()),
            evidence_type=str(
                evidence_type or "observation"
            ),
            target=str(target or "unknown"),
            description=str(description or ""),
            source_agent=str(source_agent or "unknown"),
            supports_hypothesis=bool(
                supports_hypothesis
            ),
            confidence=clamp_confidence(confidence),
            data=normalized_data,
        )

        self.evidence[evidence.id] = evidence

        return evidence

    # ------------------------------------------------------------------
    # Observation -> Evidence
    # ------------------------------------------------------------------

    def from_observation(
        self,
        observation: dict[str, Any],
        source_agent: str,
        *,
        supports_hypothesis: bool = False,
    ) -> Evidence:
        """
        Convert an agent observation into traceable evidence.

        Observations remain non-confirmatory by default.

        A later controlled validation step may explicitly mark the
        resulting evidence as supporting a hypothesis.
        """

        if not isinstance(observation, dict):
            raise TypeError(
                "Observation must be a dictionary."
            )

        source_url = (
            observation.get("source_url")
            or observation.get("url")
            or observation.get("target")
            or "unknown"
        )

        evidence_type = (
            observation.get(
                "type",
                "observation",
            )
            or "observation"
        )

        description = (
            observation.get(
                "message",
                "Agent observation.",
            )
            or "Agent observation."
        )

        confidence = clamp_confidence(
            observation.get(
                "confidence",
                0.0,
            )
        )

        data = dict(observation)

        # Guarantee traceability.
        data["source_url"] = source_url

        # Normalize severity when present.
        if "severity" in data:
            data["severity"] = normalize_severity(
                data["severity"]
            )

        # Store normalized confidence.
        data["confidence"] = confidence

        return self.create(
            evidence_type=evidence_type,
            target=source_url,
            description=description,
            source_agent=source_agent,
            supports_hypothesis=supports_hypothesis,
            confidence=confidence,
            data=data,
        )

    # ------------------------------------------------------------------
    # Storage
    # ------------------------------------------------------------------

    def add(
        self,
        evidence: Evidence,
    ) -> Evidence:
        """
        Add an existing Evidence object.

        Existing IDs are preserved and are not duplicated.
        """

        if evidence.id not in self.evidence:
            self.evidence[evidence.id] = evidence

        return evidence

    def get(
        self,
        evidence_id: str,
    ) -> Evidence | None:
        """
        Retrieve evidence by ID.
        """

        return self.evidence.get(evidence_id)

    def get_for_target(
        self,
        target: str,
    ) -> list[Evidence]:
        """
        Return all evidence associated with a target.
        """

        return [
            evidence
            for evidence in self.evidence.values()
            if evidence.target == target
        ]

    def get_supporting(
        self,
        target: str | None = None,
    ) -> list[Evidence]:
        """
        Return evidence explicitly marked as supporting a hypothesis.
        """

        evidence = [
            item
            for item in self.evidence.values()
            if item.supports_hypothesis
        ]

        if target is not None:
            evidence = [
                item
                for item in evidence
                if item.target == target
            ]

        return evidence

    def all(self) -> list[Evidence]:
        """
        Return all stored evidence.
        """

        return list(self.evidence.values())

    # ------------------------------------------------------------------
    # ManagerAgent-compatible interface
    # ------------------------------------------------------------------

    def run(
        self,
        context: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """
        ManagerAgent-compatible entry point.

        Supported observation context:

        {
            "observation": {...},
            "source_agent": "xss"
        }

        Or direct evidence context:

        {
            "evidence_type": "http_response",
            "target": "https://example.com/api/users/123",
            "description": "...",
            "source_agent": "idor",
            "supports_hypothesis": False,
            "confidence": 0.8,
            "data": {...}
        }
        """

        if not isinstance(context, dict):
            return {
                "agent": self.name,
                "status": "error",
                "error": "Context must be a dictionary.",
            }

        try:

            # Preferred path: convert an observation into evidence.
            if "observation" in context:

                evidence = self.from_observation(
                    observation=context["observation"],
                    source_agent=context.get(
                        "source_agent",
                        "unknown",
                    ),
                    supports_hypothesis=context.get(
                        "supports_hypothesis",
                        False,
                    ),
                )

            # Backward-compatible direct evidence creation.
            else:

                evidence = self.create(
                    evidence_type=context.get(
                        "evidence_type",
                        "observation",
                    ),
                    target=context.get(
                        "target",
                        "",
                    ),
                    description=context.get(
                        "description",
                        "",
                    ),
                    source_agent=context.get(
                        "source_agent",
                        "unknown",
                    ),
                    supports_hypothesis=context.get(
                        "supports_hypothesis",
                        False,
                    ),
                    confidence=context.get(
                        "confidence",
                        0.0,
                    ),
                    data=context.get(
                        "data",
                        {},
                    ),
                )

            return {
                "agent": self.name,
                "status": "success",
                "evidence": evidence,
            }

        except Exception as exc:

            return {
                "agent": self.name,
                "status": "error",
                "error": str(exc),
            }