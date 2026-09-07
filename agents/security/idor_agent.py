from __future__ import annotations

from uuid import uuid4
from typing import Any

from agents.base_agent import BaseSecurityAgent
from models.agent_result import AgentResult
from models.hypothesis import Hypothesis


class IdorAgent(BaseSecurityAgent):
    name = "idor"
    description = "Analyzes authorization and object-reference surfaces."

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

        endpoints = list(
            getattr(target_profile, "endpoints", []) or []
        )

        api_endpoints = list(
            getattr(target_profile, "api_endpoints", []) or []
        )

        authorization_relevant = bool(
            getattr(target_profile, "authorization_relevant", False)
        )

        result.observations.append({
            "type": "authorization_surface",
            "authorization_relevant": authorization_relevant,
            "endpoint_count": len(endpoints),
            "api_endpoint_count": len(api_endpoints),
        })

        if not authorization_relevant:
            result.metadata.update({
                "phase": 1,
                "implemented": True,
                "analysis_type": "recon_driven",
                "hypothesis_count": 0,
            })

            return result

        hypotheses = [
            (
                "object_reference_surface",
                "Review endpoints for object identifiers and resource references that may cross authorization boundaries.",
                "high",
            ),
            (
                "cross_user_access_surface",
                "Review resource access boundaries between users or accounts.",
                "high",
            ),
            (
                "privilege_boundary",
                "Review boundaries between normal-user and privileged functionality.",
                "high",
            ),
            (
                "resource_identifier_surface",
                "Review resource identifiers exposed through application and API endpoints.",
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
                confidence=0.65,
                priority=priority,
                status="pending",
                metadata={
                    "phase": 1,
                    "endpoint_count": len(endpoints),
                    "api_endpoint_count": len(api_endpoints),
                    "authorization_relevant": authorization_relevant,
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
