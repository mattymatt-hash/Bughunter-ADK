from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from models.validation_status import ValidationStatus


class SafeValidator:
    """
    Non-destructive validation layer.

    This validator does not submit attack payloads, bypass authentication,
    modify server state, or attempt unauthorized access.

    It validates whether existing observations contain enough direct,
    structured evidence to support a hypothesis.

    Validation states:

        NOT_TESTED
            ↓
        OBSERVED
            ↓
        VALIDATION_READY
            ↓
        VALIDATED / REJECTED / INCONCLUSIVE
    """

    name = "safe_validator"

    def validate(
        self,
        hypothesis: Any,
        observations: list[dict[str, Any]],
    ) -> dict[str, Any]:

        # -------------------------------------------------------------
        # No hypothesis
        # -------------------------------------------------------------

        if hypothesis is None:
            return self._result(
                status=ValidationStatus.INCONCLUSIVE,
                supports_hypothesis=False,
                reason="No hypothesis supplied.",
                evidence=[],
            )

        # -------------------------------------------------------------
        # No observations
        # -------------------------------------------------------------

        if not observations:
            return self._result(
                status=ValidationStatus.INCONCLUSIVE,
                supports_hypothesis=False,
                reason="No observations available.",
                evidence=[],
            )

        vulnerability_type = getattr(
            hypothesis,
            "vulnerability_type",
            "",
        )

        # -------------------------------------------------------------
        # XSS validation
        # -------------------------------------------------------------

        if vulnerability_type in {
            "reflected_input_surface",
            "stored_input_surface",
            "dom_input_surface",
        }:
            return self._validate_xss_surface(
                hypothesis,
                observations,
            )

        # -------------------------------------------------------------
        # Unsupported validation type
        # -------------------------------------------------------------

        return self._result(
            status=ValidationStatus.INCONCLUSIVE,
            supports_hypothesis=False,
            reason=(
                f"No safe validator is currently implemented for "
                f"'{vulnerability_type}'."
            ),
            evidence=[],
        )

    # -----------------------------------------------------------------
    # XSS
    # -----------------------------------------------------------------

    def _validate_xss_surface(
        self,
        hypothesis: Any,
        observations: list[dict[str, Any]],
    ) -> dict[str, Any]:

        relevant = []

        for observation in observations:

            if not isinstance(observation, dict):
                continue

            source_url = (
                observation.get("source_url")
                or observation.get("url")
                or ""
            )

            # ---------------------------------------------------------
            # Validate source URL when present.
            # ---------------------------------------------------------

            if source_url:

                parsed = urlparse(
                    str(source_url)
                )

                if parsed.scheme not in {
                    "http",
                    "https",
                }:
                    continue

            observation_type = observation.get(
                "type",
                "",
            )

            # ---------------------------------------------------------
            # Recognized XSS-relevant observations.
            # ---------------------------------------------------------

            if observation_type in {
                "html_form_input",
                "query_parameter_input",
                "javascript_input_surface",
            }:

                relevant.append(
                    {
                        "observation": observation,
                        "validation": "surface_confirmed",
                        "supports_hypothesis": False,
                        "reason": (
                            "An XSS-relevant input surface was confirmed, "
                            "but the observation does not demonstrate "
                            "executable or reflected attacker-controlled "
                            "content."
                        ),
                    }
                )

        # -------------------------------------------------------------
        # Nothing relevant found.
        # -------------------------------------------------------------

        if not relevant:
            return self._result(
                status=ValidationStatus.INCONCLUSIVE,
                supports_hypothesis=False,
                reason=(
                    "No relevant XSS input surface was observed."
                ),
                evidence=[],
            )

        # -------------------------------------------------------------
        # We have enough information to identify a validation target.
        #
        # This is NOT a confirmed vulnerability.
        # -------------------------------------------------------------

        return self._result(
            status=ValidationStatus.VALIDATION_READY,
            supports_hypothesis=False,
            reason=(
                "An XSS-relevant input surface was confirmed. "
                "The observation is sufficient to identify a target "
                "for controlled authorized validation, but it does not "
                "confirm an XSS vulnerability."
            ),
            evidence=relevant,
        )

    # -----------------------------------------------------------------
    # Result helper
    # -----------------------------------------------------------------

    def _result(
        self,
        *,
        status: ValidationStatus | str,
        supports_hypothesis: bool,
        reason: str,
        evidence: list[dict[str, Any]],
    ) -> dict[str, Any]:

        if isinstance(
            status,
            ValidationStatus,
        ):
            status_value = status.value
        else:
            status_value = str(
                status
            ).strip().lower()

        return {
            "status": status_value,
            "validation_status": status_value,
            "supports_hypothesis": bool(
                supports_hypothesis
            ),
            "reason": reason,
            "evidence": evidence,
        }