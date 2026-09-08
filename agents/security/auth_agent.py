from __future__ import annotations

from typing import Any
from uuid import uuid4

from agents.base_agent import BaseSecurityAgent
from models.agent_result import AgentResult
from models.hypothesis import Hypothesis


class AuthAgent(BaseSecurityAgent):
    name = "auth"
    description = (
        "Analyzes authentication surfaces and creates authentication "
        "security hypotheses."
    )

    def run(
        self,
        scan_result: Any,
        target_profile: Any,
        context: dict[str, Any] | None = None,
    ) -> AgentResult:

        target = (
            getattr(scan_result, "target", None)
            or getattr(target_profile, "target", "unknown")
        )

        result = AgentResult(
            agent=self.name,
            target=target,
            metadata={
                "phase": 1,
                "implemented": True,
                "analysis_type": "recon_driven",
                "destructive_testing": False,
            },
        )

        auth_endpoints = list(
            getattr(target_profile, "auth_endpoints", []) or []
        )

        authentication_present = bool(
            getattr(
                target_profile,
                "authentication_present",
                False,
            )
        )

        # ---------------------------------------------------------
        # Authentication surface summary
        # ---------------------------------------------------------

        result.add_observation({
            "type": "authentication_surface",
            "source_url": target,
            "endpoint_count": len(auth_endpoints),
            "authentication_present": authentication_present,
            "endpoints": auth_endpoints,
            "severity": "info",
            "confidence": 0.95,
        })

        # ---------------------------------------------------------
        # No authentication surface discovered
        # ---------------------------------------------------------

        if not authentication_present and not auth_endpoints:
            result.metadata.update({
                "hypothesis_count": 0,
                "observation_count": len(result.observations),
            })

            return result

        # ---------------------------------------------------------
        # Per-endpoint observations
        # ---------------------------------------------------------

        for endpoint in auth_endpoints:
            result.add_observation({
                "type": "authentication_endpoint",
                "source_url": endpoint,
                "message": (
                    "Authentication endpoint discovered; review "
                    "credential handling, session management, and "
                    "authentication boundaries."
                ),
                "severity": "info",
                "confidence": 0.95,
            })

        # ---------------------------------------------------------
        # Authentication hypotheses
        # ---------------------------------------------------------

        hypotheses = [
            (
                "login_surface",
                "Review discovered login functionality and authentication boundaries.",
                "high",
            ),
            (
                "registration_surface",
                "Review account registration functionality and account creation boundaries.",
                "medium",
            ),
            (
                "password_reset_surface",
                "Review password recovery and reset functionality.",
                "high",
            ),
            (
                "session_surface",
                "Review session-related behavior and session management surfaces.",
                "high",
            ),
            (
                "authentication_boundary",
                "Review protected and unprotected application boundaries.",
                "high",
            ),
        ]

        for vulnerability_type, description, priority in hypotheses:

            hypothesis = Hypothesis(
                id=f"{self.name}-{uuid4().hex[:12]}",
                agent=self.name,
                vulnerability_type=vulnerability_type,
                target=target,
                description=description,
                confidence=0.70,
                priority=priority,
                status="pending",
                metadata={
                    "phase": 1,
                    "auth_endpoint_count": len(auth_endpoints),
                    "authentication_present": authentication_present,
                    "auth_endpoints": auth_endpoints,
                },
            )

            result.add_hypothesis(hypothesis)

        # ---------------------------------------------------------
        # Final metadata
        # ---------------------------------------------------------

        result.metadata.update({
            "auth_endpoint_count": len(auth_endpoints),
            "authentication_present": authentication_present,
            "hypothesis_count": len(result.hypotheses),
            "observation_count": len(result.observations),
        })

        return result