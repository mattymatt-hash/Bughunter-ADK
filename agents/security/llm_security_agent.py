from __future__ import annotations

from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

from agents.base_agent import BaseSecurityAgent
from models.agent_result import AgentResult
from models.hypothesis import Hypothesis


class LlmSecurityAgent(BaseSecurityAgent):
    name = "llm_security"
    description = (
        "Analyzes discovered AI/LLM-related application surfaces "
        "for potential security risks."
    )

    LLM_PATH_INDICATORS = (
        "/chat",
        "/ai",
        "/llm",
        "/assistant",
        "/completion",
        "/completions",
        "/generate",
        "/prompt",
        "/prompts",
        "/inference",
        "/model",
        "/models",
        "/copilot",
    )

    LLM_PARAMETER_NAMES = {
        "prompt",
        "message",
        "query",
        "input",
        "instruction",
        "completion",
        "model",
        "system",
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
                "phase": 3,
                "implemented": True,
                "analysis_type": "recon_driven",
                "destructive_testing": False,
            },
        )

        surfaces: list[dict[str, Any]] = []

        llm_detected = bool(
            getattr(target_profile, "llm_detected", False)
        )

        if llm_detected:
            surfaces.append(
                {
                    "type": "profile_detection",
                    "target": target,
                }
            )

            result.add_observation(
                {
                    "type": "llm_application_surface",
                    "source_url": target,
                    "message": (
                        "LLM-related functionality was detected in "
                        "the target profile."
                    ),
                    "severity": "medium",
                    "confidence": 0.90,
                }
            )

        for url in self._get_urls(scan_result, target_profile):
            parsed = urlparse(url)
            path = parsed.path.lower()

            path_matches = [
                indicator
                for indicator in self.LLM_PATH_INDICATORS
                if indicator in path
            ]

            query_parameters = {
                key.lower()
                for key in (
                    parsed.query.split("&")
                    if parsed.query
                    else []
                )
                if key
            }

            parameter_matches = [
                parameter
                for parameter in self.LLM_PARAMETER_NAMES
                if parameter in query_parameters
            ]

            if path_matches or parameter_matches:
                surface = {
                    "url": url,
                    "path_indicators": path_matches,
                    "parameter_indicators": parameter_matches,
                }

                surfaces.append(surface)

                result.add_observation(
                    {
                        "type": "llm_endpoint_surface",
                        "source_url": url,
                        "path_indicators": path_matches,
                        "parameter_indicators": parameter_matches,
                        "message": (
                            "An endpoint containing indicators associated "
                            "with AI/LLM functionality was identified."
                        ),
                        "severity": "medium",
                        "confidence": 0.70,
                    }
                )

        result.add_observation(
            {
                "type": "llm_security_surface",
                "source_url": target,
                "surface_count": len(surfaces),
                "llm_detected": llm_detected,
                "message": (
                    f"{len(surfaces)} potential AI/LLM surface(s) "
                    "were identified."
                ),
                "severity": "info",
                "confidence": 0.90,
            }
        )

        if surfaces or llm_detected:
            hypotheses = [
                (
                    "llm_prompt_handling",
                    "Review handling and trust boundaries around user-supplied prompts.",
                    "high",
                ),
                (
                    "llm_output_handling",
                    "Review how model-generated output is processed and rendered.",
                    "high",
                ),
                (
                    "llm_authorization",
                    "Review authorization boundaries around AI/LLM functionality.",
                    "high",
                ),
                (
                    "llm_data_exposure",
                    "Review whether sensitive application data can cross LLM trust boundaries.",
                    "high",
                ),
                (
                    "llm_model_configuration",
                    "Review model and AI service configuration for security-sensitive behavior.",
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
                        "phase": 3,
                        "llm_surfaces": surfaces,
                    },
                )

                result.add_hypothesis(hypothesis)

        result.metadata.update(
            {
                "llm_detected": llm_detected,
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