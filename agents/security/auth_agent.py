from __future__ import annotations

from uuid import uuid4
from typing import Any

from agents.base_agent import BaseSecurityAgent
from models.agent_result import AgentResult
from models.hypothesis import Hypothesis


class AuthAgent(BaseSecurityAgent):
    name = "auth"
    description = "Analyzes authentication surfaces and creates authentication security hypotheses."

    def run(
        self,
        scan_result: Any,
        target_profile: Any,
        context: dict[str, Any] | None = None,
    ) -> AgentResult:

        target = getattr(
            target_profile,
            "target",
            getattr(scan_result, "target", "unknown"),
        )

        result = AgentResult(
            agent=self.name,
            target=target,
        )

        auth_endpoints = list(
            getattr(target_profile, "auth_endpoints", []) or []
        )

        authentication_present = bool(
            getattr(target_profile, "authentication_present", False)
        )

        result.observations.append({
            "type": "authentication_surface",
            "endpoint_count": len(auth_endpoints),
            "authentication_present": authentication_present,
            "endpoints": auth_endpoints,
        })

        if not authentication_present and not auth_endpoints:
            result.metadata.update({
                "phase": 1,
                "implemented": True,
                "analysis_type": "recon_driven",
                "hypothesis_count": 0,
            })

            return result

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
                },
            )

            result.add_hypothesis(hypothesis)

        result.metadata.update({
            "phase": 1,
            "implemented": True,
            "analysis_type": "recon_driven",
            "destructive_testing": False,
            "hypothesis_count": len(result.hypotheses),
            "observation_count": len(result.observations),
        })

        return result
