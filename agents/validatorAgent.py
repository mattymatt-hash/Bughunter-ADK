from models.finding import Finding
from models.hypothesis import Hypothesis


class ValidatorAgent:
    """
    Validates security hypotheses against collected evidence.

    The ValidatorAgent does not perform exploitation itself.
    Its job is to determine whether the supplied evidence supports
    the hypothesis strongly enough to become a Finding.
    """

    name = "validator"

    def __init__(self):
        self.name = "validator"

    def validate(self, hypothesis: Hypothesis, evidence: list[dict]) -> dict:
        """
        Validate a hypothesis against supplied evidence.

        Returns a structured validation result.
        """

        if not isinstance(hypothesis, Hypothesis):
            return {
                "status": "error",
                "message": "Invalid hypothesis object."
            }

        if not evidence:
            hypothesis.mark_inconclusive()

            return {
                "status": "inconclusive",
                "hypothesis": hypothesis,
                "finding": None,
                "reason": "No evidence was supplied."
            }

        hypothesis.mark_testing()

        valid_evidence = []

        for item in evidence:
            if not isinstance(item, dict):
                continue

            if not item.get("id"):
                continue

            valid_evidence.append(item)

        if not valid_evidence:
            hypothesis.mark_inconclusive()

            return {
                "status": "inconclusive",
                "hypothesis": hypothesis,
                "finding": None,
                "reason": "No usable evidence was supplied."
            }

        for item in valid_evidence:
            hypothesis.add_evidence(item["id"])

        # Evidence must explicitly support the hypothesis.
        supporting = [
            item
            for item in valid_evidence
            if item.get("supports_hypothesis") is True
        ]

        if not supporting:
            hypothesis.mark_rejected()

            return {
                "status": "rejected",
                "hypothesis": hypothesis,
                "finding": None,
                "reason": "Evidence does not explicitly support the hypothesis."
            }

        hypothesis.mark_supported()

        finding = Finding(
            id=f"finding-{hypothesis.id}",
            vulnerability_type=hypothesis.vulnerability_type,
            title=f"{hypothesis.vulnerability_type} detected",
            target=hypothesis.target,
            description=hypothesis.description,
            confidence=self._calculate_confidence(
                hypothesis,
                supporting
            ),
            agent=hypothesis.agent,
            evidence_ids=[
                item["id"]
                for item in supporting
            ],
        )

        return {
            "status": "confirmed",
            "hypothesis": hypothesis,
            "finding": finding,
            "evidence": supporting,
        }

    def _calculate_confidence(
        self,
        hypothesis: Hypothesis,
        evidence: list[dict]
    ) -> float:
        """
        Calculate confidence from the hypothesis and supporting evidence.
        """

        base = max(0.0, min(1.0, hypothesis.confidence))

        if not evidence:
            return base

        # Each independent supporting observation increases confidence,
        # with diminishing returns.
        bonus = min(0.35, len(evidence) * 0.10)

        return round(min(1.0, base + bonus), 2)

    def run(self, context):
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
                "error": "Context must be a dictionary."
            }

        hypothesis = context.get("hypothesis")
        evidence = context.get("evidence", [])

        result = self.validate(
            hypothesis,
            evidence
        )

        return {
            "agent": self.name,
            **result,
        }