from __future__ import annotations

from typing import Any

from models.finding import Finding
from models.hypothesis import Hypothesis
from models.security_rating import (
    clamp_confidence,
    normalize_severity,
)


class ValidatorAgent:
    """
    Validates security hypotheses against collected evidence.

    The ValidatorAgent does not perform exploitation itself.
    Its job is to determine whether supplied evidence actually
    supports the hypothesis strongly enough to become a Finding.
    """

    name = "validator"

    def __init__(self) -> None:
        self.name = "validator"

    def validate(
        self,
        hypothesis: Hypothesis,
        evidence: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """
        Validate a hypothesis against supplied evidence.

        Observational evidence alone cannot create a finding.
        Evidence must explicitly set supports_hypothesis=True.
        """

        # --------------------------------------------------------------
        # Validate hypothesis
        # --------------------------------------------------------------

        if not isinstance(hypothesis, Hypothesis):
            return {
                "status": "error",
                "message": "Invalid hypothesis object.",
                "finding": None,
            }

        # --------------------------------------------------------------
        # Require evidence
        # --------------------------------------------------------------

        if not evidence:
            if hasattr(hypothesis, "mark_inconclusive"):
                hypothesis.mark_inconclusive()

            return {
                "status": "inconclusive",
                "hypothesis": hypothesis,
                "finding": None,
                "evidence": [],
                "reason": "No evidence was supplied.",
            }

        # --------------------------------------------------------------
        # Filter usable evidence
        # --------------------------------------------------------------

        valid_evidence: list[dict[str, Any]] = []

        for item in evidence:
            if not isinstance(item, dict):
                continue

            if not item.get("id"):
                continue

            valid_evidence.append(item)

        if not valid_evidence:
            if hasattr(hypothesis, "mark_inconclusive"):
                hypothesis.mark_inconclusive()

            return {
                "status": "inconclusive",
                "hypothesis": hypothesis,
                "finding": None,
                "evidence": [],
                "reason": "No usable evidence was supplied.",
            }

        # --------------------------------------------------------------
        # Mark hypothesis as being tested
        # --------------------------------------------------------------

        if hasattr(hypothesis, "mark_testing"):
            hypothesis.mark_testing()

        # --------------------------------------------------------------
        # Attach evidence IDs to hypothesis
        # --------------------------------------------------------------

        evidence_ids = [
            item["id"]
            for item in valid_evidence
        ]

        if hasattr(hypothesis, "evidence_ids"):
            # Use the model's method when available.
            if hasattr(hypothesis, "add_evidence"):
                for evidence_id in evidence_ids:
                    hypothesis.add_evidence(evidence_id)
            else:
                hypothesis.evidence_ids = evidence_ids

        # --------------------------------------------------------------
        # Identify explicitly supporting evidence
        # --------------------------------------------------------------

        supporting = [
            item
            for item in valid_evidence
            if item.get("supports_hypothesis") is True
        ]

        # --------------------------------------------------------------
        # Observational evidence is NOT enough
        # --------------------------------------------------------------

        if not supporting:

            if hasattr(hypothesis, "mark_rejected"):
                hypothesis.mark_rejected()

            return {
                "status": "rejected",
                "hypothesis": hypothesis,
                "finding": None,
                "evidence": valid_evidence,
                "evidence_ids": evidence_ids,
                "reason": (
                    "Evidence is observational or otherwise "
                    "does not explicitly support the hypothesis."
                ),
            }

        # --------------------------------------------------------------
        # Hypothesis is supported
        # --------------------------------------------------------------

        if hasattr(hypothesis, "mark_supported"):
            hypothesis.mark_supported()

        # --------------------------------------------------------------
        # Determine severity
        # --------------------------------------------------------------

        severity_candidates = [
            item.get("severity")
            for item in supporting
            if item.get("severity")
        ]

        if severity_candidates:
            severity = normalize_severity(
                severity_candidates[0]
            )
        else:
            severity = normalize_severity(
                getattr(
                    hypothesis,
                    "severity",
                    "medium",
                )
            )

        # --------------------------------------------------------------
        # Calculate confidence
        # --------------------------------------------------------------

        confidence = self._calculate_confidence(
            hypothesis,
            supporting,
        )

        # --------------------------------------------------------------
        # Create validated finding
        # --------------------------------------------------------------

        finding = Finding(
            id=f"finding-{hypothesis.id}",
            vulnerability_type=hypothesis.vulnerability_type,
            title=(
                getattr(
                    hypothesis,
                    "title",
                    None,
                )
                or f"{hypothesis.vulnerability_type} detected"
            ),
            target=hypothesis.target,
            description=hypothesis.description,
            confidence=confidence,
            agent=hypothesis.agent,
            evidence_ids=[
                item["id"]
                for item in supporting
            ],
        )

        # Finding models that support severity receive it.
        if hasattr(finding, "severity"):
            finding.severity = severity

        return {
            "status": "confirmed",
            "hypothesis": hypothesis,
            "finding": finding,
            "evidence": supporting,
            "evidence_ids": [
                item["id"]
                for item in supporting
            ],
            "severity": severity,
            "confidence": confidence,
        }

    # ------------------------------------------------------------------
    # Confidence
    # ------------------------------------------------------------------

    def _calculate_confidence(
        self,
        hypothesis: Hypothesis,
        evidence: list[dict[str, Any]],
    ) -> float:
        """
        Calculate confidence from the hypothesis and supporting evidence.

        Starts with the hypothesis confidence and adds a bounded
        confidence bonus based on the quality of supporting evidence.
        """

        base = clamp_confidence(
            getattr(
                hypothesis,
                "confidence",
                0.0,
            )
        )

        if not evidence:
            return round(base, 3)

        evidence_confidences = [
            clamp_confidence(
                item.get(
                    "confidence",
                    0.0,
                )
            )
            for item in evidence
        ]

        average_confidence = (
            sum(evidence_confidences)
            / len(evidence_confidences)
        )

        # Supporting evidence can increase confidence by up to 0.35.
        bonus = min(
            0.35,
            average_confidence * 0.35,
        )

        return round(
            min(
                1.0,
                base + bonus,
            ),
            3,
        )

    # ------------------------------------------------------------------
    # ManagerAgent-compatible interface
    # ------------------------------------------------------------------

    def run(
        self,
        context: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """
        ManagerAgent-compatible entry point.

        Expected context:

        {
            "hypothesis": Hypothesis(...),
            "evidence": [...]
        }
        """

        if not isinstance(context, dict):
            return {
                "agent": self.name,
                "status": "error",
                "error": "Context must be a dictionary.",
            }

        hypothesis = context.get(
            "hypothesis"
        )

        evidence = context.get(
            "evidence",
            [],
        )

        result = self.validate(
            hypothesis,
            evidence,
        )

        return {
            "agent": self.name,
            **result,
        }