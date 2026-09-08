from __future__ import annotations

from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

from agents.base_agent import BaseSecurityAgent
from models.agent_result import AgentResult
from models.hypothesis import Hypothesis


class CsrfAgent(BaseSecurityAgent):
    name = "csrf"
    description = (
        "Analyzes state-changing form and HTTP method surfaces for "
        "cross-site request forgery risk."
    )

    CSRF_TOKEN_NAMES = {
        "csrf",
        "csrf_token",
        "xsrf",
        "xsrf_token",
        "_csrf",
        "_token",
        "authenticity_token",
    }

    STATE_CHANGING_METHODS = {
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
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

        form_surfaces = []

        for url in self._get_urls(scan_result, target_profile):
            parsed = urlparse(url)

            if parsed.scheme not in {"http", "https"}:
                continue

            form_surfaces.append(
                {
                    "url": url,
                    "method": "unknown",
                }
            )

        methods = getattr(scan_result, "http_methods", []) or []

        for method_result in methods:
            method_data = getattr(
                method_result,
                "__dict__",
                {},
            )

            method = str(
                method_data.get("method", "")
            ).upper()

            if method in self.STATE_CHANGING_METHODS:
                result.add_observation(
                    {
                        "type": "csrf_state_changing_method",
                        "source_url": target,
                        "method": method,
                        "message": (
                            f"{method} is supported and represents a "
                            "potential state-changing request surface."
                        ),
                        "severity": "low",
                        "confidence": 0.75,
                    }
                )

        result.add_observation(
            {
                "type": "csrf_surface",
                "source_url": target,
                "surface_count": len(form_surfaces),
                "message": (
                    f"{len(form_surfaces)} application URL surface(s) "
                    "are available for CSRF review."
                ),
                "severity": "info",
                "confidence": 0.85,
            }
        )

        if form_surfaces:
            hypotheses = [
                (
                    "csrf_form_surface",
                    "Review state-changing forms for CSRF protection.",
                    "high",
                ),
                (
                    "csrf_state_change_surface",
                    "Review state-changing HTTP request surfaces.",
                    "high",
                ),
                (
                    "csrf_token_surface",
                    "Review application use of CSRF protection tokens.",
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
                        "phase": 2,
                        "form_surfaces": form_surfaces,
                    },
                )

                result.add_hypothesis(hypothesis)

        result.metadata.update(
            {
                "form_surface_count": len(form_surfaces),
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

        return urls