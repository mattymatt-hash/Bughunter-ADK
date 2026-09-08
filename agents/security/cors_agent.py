from __future__ import annotations

from typing import Any
from uuid import uuid4

from agents.base_agent import BaseSecurityAgent
from models.agent_result import AgentResult
from models.hypothesis import Hypothesis


class CorsAgent(BaseSecurityAgent):
    name = "cors"
    description = (
        "Analyzes HTTP cross-origin configuration and CORS-related "
        "response headers."
    )

    CORS_HEADERS = {
        "access-control-allow-origin",
        "access-control-allow-credentials",
        "access-control-allow-methods",
        "access-control-allow-headers",
        "access-control-expose-headers",
        "access-control-max-age",
    }

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

        header_results = getattr(
            scan_result,
            "header_results",
            [],
        ) or []

        cors_surfaces = []

        for header_result in header_results:
            data = getattr(
                header_result,
                "__dict__",
                {},
            )

            url = (
                data.get("source_url")
                or data.get("url")
                or target
            )

            headers = data.get("headers", {}) or {}

            cors_headers = {}

            for name, value in headers.items():
                if str(name).lower() in self.CORS_HEADERS:
                    cors_headers[str(name).lower()] = value

            if cors_headers:
                cors_surfaces.append(
                    {
                        "url": url,
                        "headers": cors_headers,
                    }
                )

                allow_origin = cors_headers.get(
                    "access-control-allow-origin"
                )

                allow_credentials = cors_headers.get(
                    "access-control-allow-credentials"
                )

                severity = "info"

                if allow_origin == "*":
                    severity = "low"

                if (
                    allow_origin == "*"
                    and str(allow_credentials).lower() == "true"
                ):
                    severity = "medium"

                result.add_observation(
                    {
                        "type": "cors_configuration",
                        "source_url": url,
                        "allow_origin": allow_origin,
                        "allow_credentials": allow_credentials,
                        "headers": cors_headers,
                        "message": (
                            "CORS-related response headers were observed "
                            "during passive analysis."
                        ),
                        "severity": severity,
                        "confidence": 0.90,
                    }
                )

        if not cors_surfaces:
            result.add_observation(
                {
                    "type": "cors_surface",
                    "source_url": target,
                    "message": (
                        "No CORS response headers were identified in "
                        "the available reconnaissance data."
                    ),
                    "severity": "info",
                    "confidence": 0.85,
                }
            )

        if cors_surfaces:
            hypotheses = [
                (
                    "cors_configuration",
                    "Review discovered CORS configuration for cross-origin security risks.",
                    "medium",
                ),
                (
                    "cors_origin_policy",
                    "Review Access-Control-Allow-Origin behavior and origin trust boundaries.",
                    "medium",
                ),
                (
                    "cors_credentials_policy",
                    "Review CORS credential configuration and cross-origin authentication boundaries.",
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
                        "cors_surfaces": cors_surfaces,
                    },
                )

                result.add_hypothesis(hypothesis)

        result.metadata.update(
            {
                "cors_surface_count": len(cors_surfaces),
                "hypothesis_count": len(result.hypotheses),
                "observation_count": len(result.observations),
            }
        )

        return result