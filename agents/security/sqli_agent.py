from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlparse
from uuid import uuid4

from agents.base_agent import BaseSecurityAgent
from models.agent_result import AgentResult
from models.hypothesis import Hypothesis


class SqliAgent(BaseSecurityAgent):
    name = "sqli"
    description = (
        "Analyzes discovered input surfaces for SQL injection-relevant "
        "parameters and creates security hypotheses."
    )

    SQL_PARAMETER_NAMES = {
        "id",
        "uid",
        "user_id",
        "account_id",
        "item_id",
        "product_id",
        "order_id",
        "invoice_id",
        "category",
        "search",
        "query",
        "q",
        "filter",
        "sort",
        "order",
        "limit",
        "offset",
        "page",
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

        urls = self._get_urls(scan_result, target_profile)

        parameter_surfaces = []

        for url in urls:
            parsed = urlparse(url)
            parameters = parse_qs(parsed.query)

            for parameter in parameters:
                parameter_lower = parameter.lower()

                if (
                    parameter_lower in self.SQL_PARAMETER_NAMES
                    or parameter_lower.endswith("_id")
                ):
                    parameter_surfaces.append(
                        {
                            "url": url,
                            "parameter": parameter,
                        }
                    )

                    result.add_observation(
                        {
                            "type": "sqli_input_surface",
                            "source_url": url,
                            "parameter": parameter,
                            "message": (
                                "A SQL-injection-relevant input parameter "
                                "was identified during passive analysis."
                            ),
                            "severity": "low",
                            "confidence": 0.70,
                        }
                    )

        result.add_observation(
            {
                "type": "sqli_surface",
                "source_url": target,
                "parameter_count": len(parameter_surfaces),
                "message": (
                    f"{len(parameter_surfaces)} SQL-injection-relevant "
                    "parameter surface(s) identified."
                ),
                "severity": "info",
                "confidence": 0.90,
            }
        )

        if parameter_surfaces:
            hypotheses = [
                (
                    "sqli_parameter_surface",
                    "Review discovered parameters for SQL injection risk.",
                    "high",
                ),
                (
                    "sqli_numeric_parameter",
                    "Review numeric or identifier parameters for SQL injection risk.",
                    "medium",
                ),
                (
                    "sqli_search_surface",
                    "Review search and query parameters for SQL injection risk.",
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
                        "parameter_surfaces": parameter_surfaces,
                    },
                )

                result.add_hypothesis(hypothesis)

        result.metadata.update(
            {
                "parameter_surface_count": len(parameter_surfaces),
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

        scan_urls = getattr(scan_result, "urls", []) or []

        for item in scan_urls:
            url = getattr(item, "url", None)

            if url and url not in urls:
                urls.append(url)

        profile_urls = (
            getattr(target_profile, "endpoints", []) or []
        )

        for url in profile_urls:
            if url and url not in urls:
                urls.append(url)

        return urls