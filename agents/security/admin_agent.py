from __future__ import annotations

from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

from agents.base_agent import BaseSecurityAgent
from models.agent_result import AgentResult
from models.hypothesis import Hypothesis


class AdminAgent(BaseSecurityAgent):
    name = "admin"
    description = (
        "Analyzes discovered administrative and privileged application "
        "surfaces."
    )

    ADMIN_PATHS = (
        "/admin",
        "/administrator",
        "/management",
        "/manage",
        "/control",
        "/staff",
        "/moderator",
        "/dashboard",
        "/backend",
        "/control-panel",
    )

    def run(
        self,
        scan_result: Any,
        target_profile: Any,
        context: dict[str, Any] | None = None,
    ) -> AgentResult:

        target = (
            getattr(scan_result, "target", None)
            or getattr(target_profile, "target", None)
            or "unknown"
        )

        result = AgentResult(
            agent=self.name,
            target=target,
            metadata={
                "phase": 2,
                "implemented": True,
                "analysis_type": "recon_driven",
                "destructive_testing": False,
            },
        )

        admin_surfaces: list[str] = []

        profile_admin = (
            getattr(target_profile, "admin_endpoints", [])
            or []
        )

        profile_dashboard = (
            getattr(target_profile, "dashboard_endpoints", [])
            or []
        )

        for endpoint in profile_admin + profile_dashboard:
            if endpoint and endpoint not in admin_surfaces:
                admin_surfaces.append(endpoint)

        for item in getattr(scan_result, "urls", []) or []:
            url = getattr(item, "url", None)

            if not url:
                continue

            parsed = urlparse(url)
            path = parsed.path.lower()

            for indicator in self.ADMIN_PATHS:
                if path == indicator or path.startswith(indicator + "/"):
                    if url not in admin_surfaces:
                        admin_surfaces.append(url)

                    break

        for endpoint in admin_surfaces:
            result.add_observation(
                {
                    "type": "admin_surface",
                    "source_url": endpoint,
                    "message": (
                        "An administrative or privileged application "
                        "surface was identified during passive analysis."
                    ),
                    "severity": "info",
                    "confidence": 0.90,
                }
            )

        result.add_observation(
            {
                "type": "admin_surface_summary",
                "source_url": target,
                "endpoint_count": len(admin_surfaces),
                "message": (
                    f"{len(admin_surfaces)} administrative surface(s) "
                    "were identified."
                ),
                "severity": "info",
                "confidence": 0.90,
            }
        )

        if admin_surfaces:
            hypotheses = [
                (
                    "admin_surface",
                    "Review discovered administrative functionality.",
                    "medium",
                ),
                (
                    "admin_authentication_boundary",
                    "Review authentication requirements for administrative functionality.",
                    "high",
                ),
                (
                    "admin_authorization_boundary",
                    "Review authorization boundaries protecting administrative functionality.",
                    "high",
                ),
                (
                    "privileged_functionality",
                    "Review privileged application functionality for access-control risks.",
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
                        "phase": 2,
                        "admin_endpoints": admin_surfaces,
                    },
                )

                result.add_hypothesis(hypothesis)

        result.metadata.update(
            {
                "admin_surface_count": len(admin_surfaces),
                "hypothesis_count": len(result.hypotheses),
                "observation_count": len(result.observations),
            }
        )

        return result