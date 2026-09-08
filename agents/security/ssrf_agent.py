from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

from agents.base_agent import BaseSecurityAgent
from models.agent_result import AgentResult
from models.hypothesis import Hypothesis


class SsrfAgent(BaseSecurityAgent):
    name = "ssrf"
    description = (
        "Analyzes discovered URL-fetching and callback surfaces for "
        "server-side request forgery risk."
    )

    URL_PARAMETER_NAMES = {
        "url",
        "uri",
        "endpoint",
        "callback",
        "redirect",
        "return_url",
        "next",
        "target",
        "destination",
        "source",
        "image",
        "avatar",
        "remote",
        "proxy",
        "fetch",
        "import",
        "webhook",
    }

    URL_PATH_INDICATORS = (
        "/proxy",
        "/fetch",
        "/import",
        "/webhook",
        "/callback",
        "/redirect",
        "/remote",
        "/external",
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

        urls = self._get_urls(scan_result, target_profile)

        surfaces = []

        for url in urls:
            parsed = urlparse(url)

            parameters = parse_qs(parsed.query)

            for parameter in parameters:
                if parameter.lower() in self.URL_PARAMETER_NAMES:
                    surfaces.append(
                        {
                            "url": url,
                            "parameter": parameter,
                        }
                    )

                    result.add_observation(
                        {
                            "type": "ssrf_url_input",
                            "source_url": url,
                            "parameter": parameter,
                            "message": (
                                "A parameter capable of representing a "
                                "URL or remote resource was identified."
                            ),
                            "severity": "medium",
                            "confidence": 0.70,
                        }
                    )

            path = parsed.path.lower()

            for indicator in self.URL_PATH_INDICATORS:
                if indicator in path:
                    surfaces.append(
                        {
                            "url": url,
                            "path_indicator": indicator,
                        }
                    )

                    result.add_observation(
                        {
                            "type": "ssrf_endpoint_surface",
                            "source_url": url,
                            "path_indicator": indicator,
                            "message": (
                                "The endpoint path contains an indicator "
                                "associated with server-side URL fetching "
                                "or callback functionality."
                            ),
                            "severity": "medium",
                            "confidence": 0.65,
                        }
                    )

        result.add_observation(
            {
                "type": "ssrf_surface",
                "source_url": target,
                "surface_count": len(surfaces),
                "message": (
                    f"{len(surfaces)} potential server-side URL-fetching "
                    "surface(s) identified."
                ),
                "severity": "info",
                "confidence": 0.90,
            }
        )

        if surfaces:
            hypotheses = [
                (
                    "ssrf_url_fetch_surface",
                    "Review URL and remote-resource inputs for SSRF risk.",
                    "high",
                ),
                (
                    "ssrf_callback_surface",
                    "Review callback and webhook functionality for SSRF risk.",
                    "high",
                ),
                (
                    "ssrf_remote_resource_surface",
                    "Review remote-resource processing functionality.",
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
                        "phase": 2,
                        "surfaces": surfaces,
                    },
                )

                result.add_hypothesis(hypothesis)

        result.metadata.update(
            {
                "surface_count": len(surfaces),
                "hypothesis_count": len(result.hypotheses),
                "observation_count": len(result.observations),
            }
        )

        return result

    def _get_urls(
        self,
        scan_result: Any,
        target_profile: Any,
    ) -> list[str]:

        urls: list[str] = []

        for item in getattr(scan_result, "urls", []) or []:
            url = getattr(item, "url", None)

            if url and url not in urls:
                urls.append(url)

        for url in getattr(target_profile, "endpoints", []) or []:
            if url and url not in urls:
                urls.append(url)

        for url in getattr(target_profile, "api_endpoints", []) or []:
            if url and url not in urls:
                urls.append(url)

        return urls