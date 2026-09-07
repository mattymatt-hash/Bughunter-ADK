from __future__ import annotations

from uuid import uuid4
from typing import Any

from agents.base_agent import BaseSecurityAgent
from models.agent_result import AgentResult
from models.hypothesis import Hypothesis


class ApiAgent(BaseSecurityAgent):
    name = "api"
    description = "Analyzes discovered API surfaces and creates API security hypotheses."

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

        api_endpoints = list(
            getattr(target_profile, "api_endpoints", []) or []
        )

        if not api_endpoints:
            result.observations.append({
                "type": "api_surface",
                "endpoint_count": 0,
                "message": "No API endpoints identified.",
            })

            result.metadata.update({
                "phase": 1,
                "implemented": True,
                "analysis_type": "recon_driven",
                "hypothesis_count": 0,
            })

            return result

        result.observations.append({
            "type": "api_surface",
            "endpoint_count": len(api_endpoints),
            "endpoints": api_endpoints,
        })

        hypotheses = [
            (
                "api_endpoint_inventory",
                "Review discovered API endpoints for exposed functionality and security-sensitive resources.",
                "high",
            ),
            (
                "api_parameter_surface",
                "Review API endpoints for user-controlled parameters and input handling.",
                "medium",
            ),
            (
                "api_authentication_surface",
                "Review API endpoints for authentication requirements and authentication boundaries.",
                "high",
            ),
            (
                "api_authorization_surface",
                "Review API endpoints for authorization requirements and resource access boundaries.",
                "high",
            ),
            (
                "api_method_surface",
                "Review supported HTTP methods and method-specific security behavior across API endpoints.",
                "medium",
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
                    "endpoint_count": len(api_endpoints),
                    "endpoints": api_endpoints,
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
