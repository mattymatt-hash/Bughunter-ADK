from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from models.security_rating import (
    clamp_confidence,
    normalize_severity,
)
from models.validation_status import ValidationStatus


@dataclass
class AgentResult:
    """
    Standard result returned by every BugHunter security agent.

    AgentResult provides a common structure for:

    - observations
    - hypotheses
    - evidence
    - findings
    - errors
    - validation state
    - execution metadata
    """

    agent: str
    target: str

    status: str = "completed"

    # ---------------------------------------------------------------
    # Validation state
    # ---------------------------------------------------------------

    validation_status: str = ValidationStatus.NOT_TESTED.value

    hypotheses: list[Any] = field(default_factory=list)
    evidence: list[Any] = field(default_factory=list)
    observations: list[Any] = field(default_factory=list)
    findings: list[Any] = field(default_factory=list)

    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    # ---------------------------------------------------------------
    # Status
    # ---------------------------------------------------------------

    @property
    def success(self) -> bool:
        """
        Return True when the agent completed successfully or partially.
        """

        return self.status in {
            "completed",
            "partial",
        }

    # ---------------------------------------------------------------
    # Validation state
    # ---------------------------------------------------------------

    def set_validation_status(
        self,
        status: str | ValidationStatus,
    ) -> None:
        """
        Set the validation state using the controlled enum values.
        """

        if isinstance(status, ValidationStatus):
            self.validation_status = status.value
            return

        normalized = str(
            status or ""
        ).strip().lower()

        valid_states = {
            state.value
            for state in ValidationStatus
        }

        if normalized not in valid_states:
            raise ValueError(
                f"Invalid validation status: {status}"
            )

        self.validation_status = normalized

    # ---------------------------------------------------------------
    # Hypotheses
    # ---------------------------------------------------------------

    def add_hypothesis(
        self,
        hypothesis: Any,
    ) -> None:
        """
        Add a hypothesis produced by the agent.
        """

        self.hypotheses.append(
            hypothesis
        )

    # ---------------------------------------------------------------
    # Evidence
    # ---------------------------------------------------------------

    def add_evidence(
        self,
        evidence: Any,
    ) -> None:
        """
        Add evidence associated with this agent result.
        """

        self.evidence.append(
            evidence
        )

    # ---------------------------------------------------------------
    # Observations
    # ---------------------------------------------------------------

    def add_observation(
        self,
        observation: Any,
    ) -> None:
        """
        Add an observation and normalize its security metadata.

        Dictionary observations receive:

        - severity
        - confidence
        - source_url

        Adding an observation moves validation state from
        NOT_TESTED to OBSERVED.

        OBSERVED does not mean the hypothesis is confirmed.
        """

        if isinstance(observation, dict):

            # Default severity.
            observation.setdefault(
                "severity",
                "info",
            )

            observation["severity"] = (
                normalize_severity(
                    observation.get(
                        "severity",
                        "info",
                    )
                )
            )

            # Default confidence.
            observation.setdefault(
                "confidence",
                0.0,
            )

            observation["confidence"] = (
                clamp_confidence(
                    observation.get(
                        "confidence",
                        0.0,
                    )
                )
            )

            # Preserve source URL for report traceability.
            if not observation.get("source_url"):

                observation["source_url"] = (
                    observation.get("url")
                    or observation.get("target")
                    or self.target
                )

        self.observations.append(
            observation
        )

        # An observation means the agent has
        # moved beyond NOT_TESTED.
        #
        # It does NOT mean the hypothesis is validated.
        if (
            self.validation_status
            == ValidationStatus.NOT_TESTED.value
        ):
            self.validation_status = (
                ValidationStatus.OBSERVED.value
            )

    # ---------------------------------------------------------------
    # Findings
    # ---------------------------------------------------------------

    def add_finding(
        self,
        finding: Any,
    ) -> None:
        """
        Add a validated security finding.
        """

        self.findings.append(
            finding
        )

    # ---------------------------------------------------------------
    # Errors
    # ---------------------------------------------------------------

    def add_error(
        self,
        error: str,
    ) -> None:
        """
        Record an agent error.

        A completed agent becomes partial when
        an error is recorded.

        If validation has not started, the state
        becomes INCONCLUSIVE.
        """

        self.errors.append(
            str(error)
        )

        if self.status == "completed":
            self.status = "partial"

        if (
            self.validation_status
            == ValidationStatus.NOT_TESTED.value
        ):
            self.validation_status = (
                ValidationStatus.INCONCLUSIVE.value
            )