from __future__ import annotations

from uuid import uuid4
from typing import Any
from urllib.parse import urlparse, parse_qs

from agents.base_agent import BaseSecurityAgent
from models.agent_result import AgentResult
from models.hypothesis import Hypothesis


class IdorAgent(BaseSecurityAgent):
    name = "idor"
    description = "Analyzes authorization and object-reference surfaces."

    OBJECT_REFERENCE_TOKENS = (
        "/user/",
        "/users/",
        "/account/",
        "/accounts/",
        "/profile/",
        "/profiles/",
        "/order/",
        "/orders/",
        "/invoice/",
        "/invoices/",
        "/document/",
        "/documents/",
        "/file/",
        "/files/",
        "/message/",
        "/messages/",
        "/project/",
        "/projects/",
        "/resource/",
        "/resources/",
        "id=",
        "user_id=",
        "account_id=",
        "profile_id=",
        "order_id=",
        "invoice_id=",
        "document_id=",
        "file_id=",
        "project_id=",
        "resource_id=",
    )

    def run(
        self,
        scan_result: Any,
        target_profile: Any,
        context: dict[str, Any] | None = None,
    ) -> AgentResult:

        target = (
            getattr(target_profile, "target", None)
            or getattr(scan_result, "target", "unknown")
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

        endpoints = list(
            getattr(target_profile, "endpoints", []) or []
        )

        api_endpoints = list(
            getattr(target_profile, "api_endpoints", []) or []
        )

        authorization_relevant = bool(
            getattr(target_profile, "authorization_relevant", False)
        )

        # Combine normal and API endpoints without duplicates.
        all_endpoints = []
        seen = set()

        for endpoint in endpoints + api_endpoints:
            if not endpoint:
                continue

            endpoint = str(endpoint)

            if endpoint not in seen:
                seen.add(endpoint)
                all_endpoints.append(endpoint)

        # General authorization-surface observation.
        result.add_observation({
            "type": "authorization_surface",
            "source_url": target,
            "authorization_relevant": authorization_relevant,
            "endpoint_count": len(endpoints),
            "api_endpoint_count": len(api_endpoints),
            "message": (
                "Authorization-relevant application surfaces were reviewed "
                "for potential object references and access-control boundaries."
            ),
            "severity": "info",
            "confidence": 0.95,
        })

        # If reconnaissance does not indicate authorization relevance,
        # do not manufacture IDOR hypotheses.
        if not authorization_relevant:
            result.metadata.update({
                "hypothesis_count": 0,
                "observation_count": len(result.observations),
                "object_reference_count": 0,
            })

            return result

        object_reference_endpoints = []

        # Inspect discovered endpoints for likely object references.
        for endpoint in all_endpoints:
            endpoint_lower = endpoint.lower()

            parsed = urlparse(endpoint)
            query_parameters = parse_qs(parsed.query)

            has_token = any(
                token in endpoint_lower
                for token in self.OBJECT_REFERENCE_TOKENS
            )

            has_identifier_parameter = any(
                parameter.lower().endswith(
                    (
                        "_id",
                        "id",
                    )
                )
                for parameter in query_parameters
            )

            if not has_token and not has_identifier_parameter:
                continue

            object_reference_endpoints.append(endpoint)

            result.add_observation({
                "type": "object_reference_surface",
                "source_url": endpoint,
                "message": (
                    "URL appears to contain an object reference and warrants "
                    "authorization review; no access-control bypass was attempted."
                ),
                "severity": "low",
                "confidence": 0.80,
                "query_parameters": sorted(query_parameters.keys()),
            })

        # Broader authorization hypotheses.
        hypotheses = [
            (
                "object_reference_surface",
                "Review endpoints for object identifiers and resource references "
                "that may cross authorization boundaries.",
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
                    "object_reference_count": len(
                        object_reference_endpoints
                    ),
                    "object_reference_endpoints": (
                        object_reference_endpoints
                    ),
                },
            )

            result.add_hypothesis(hypothesis)

        result.metadata.update({
            "phase": 1,
            "implemented": True,
            "analysis_type": "recon_driven",
            "destructive_testing": False,
            "endpoint_count": len(endpoints),
            "api_endpoint_count": len(api_endpoints),
            "authorization_relevant": authorization_relevant,
            "object_reference_count": len(
                object_reference_endpoints
            ),
            "hypothesis_count": len(result.hypotheses),
            "observation_count": len(result.observations),
        })

        return result