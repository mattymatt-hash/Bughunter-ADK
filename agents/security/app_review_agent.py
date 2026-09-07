from __future__ import annotations

from typing import Any
from uuid import uuid4

from agents.base_agent import BaseSecurityAgent
from models.agent_result import AgentResult
from models.hypothesis import Hypothesis


class AppReviewAgent(BaseSecurityAgent):
    """
    Phase 1 application review agent.

    Performs non-destructive analysis of reconnaissance data and
    identifies application-surface areas that deserve further review.
    """

    name = "app_review"
    description = (
        "Reviews the discovered application surface, technologies, "
        "endpoints, authentication, APIs, and security indicators."
    )

    def run(
        self,
        scan_result: Any,
        target_profile: Any,
        context: dict[str, Any] | None = None,
    ) -> AgentResult:
        target = self._get_target(scan_result, target_profile)

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

        if scan_result is None and target_profile is None:
            result.add_error(
                "AppReviewAgent requires ScanResult or TargetProfile."
            )
            return result

        endpoints = self._get_list(target_profile, "endpoints")
        technologies = self._get_list(target_profile, "technologies")
        api_endpoints = self._get_list(target_profile, "api_endpoints")
        auth_endpoints = self._get_list(target_profile, "auth_endpoints")
        admin_endpoints = self._get_list(target_profile, "admin_endpoints")
        upload_endpoints = self._get_list(target_profile, "upload_endpoints")
        download_endpoints = self._get_list(target_profile, "download_endpoints")

        result.add_observation({
            "type": "application_surface",
            "endpoint_count": len(endpoints),
            "technology_count": len(technologies),
            "api_endpoint_count": len(api_endpoints),
            "auth_endpoint_count": len(auth_endpoints),
            "admin_endpoint_count": len(admin_endpoints),
            "upload_endpoint_count": len(upload_endpoints),
            "download_endpoint_count": len(download_endpoints),
        })

        if technologies:
            result.add_observation({
                "type": "technology_stack",
                "technologies": technologies,
            })

        authentication_present = bool(
            getattr(target_profile, "authentication_present", False)
        )

        authorization_relevant = bool(
            getattr(target_profile, "authorization_relevant", False)
        )

        if authentication_present:
            result.add_observation({
                "type": "authentication_surface",
                "authentication_present": True,
                "endpoint_count": len(auth_endpoints),
            })

        if authorization_relevant:
            result.add_observation({
                "type": "authorization_surface",
                "authorization_relevant": True,
                "endpoint_count": len(endpoints),
            })

        if api_endpoints:
            result.add_observation({
                "type": "api_surface",
                "endpoints": api_endpoints,
                "endpoint_count": len(api_endpoints),
            })

        if admin_endpoints:
            result.add_observation({
                "type": "administrative_surface",
                "endpoints": admin_endpoints,
                "endpoint_count": len(admin_endpoints),
            })

        if upload_endpoints:
            result.add_observation({
                "type": "file_upload_surface",
                "endpoints": upload_endpoints,
                "endpoint_count": len(upload_endpoints),
            })

        if download_endpoints:
            result.add_observation({
                "type": "file_download_surface",
                "endpoints": download_endpoints,
                "endpoint_count": len(download_endpoints),
            })

        indicators = {
            "graphql_detected": bool(
                getattr(target_profile, "graphql_detected", False)
            ),
            "websocket_detected": bool(
                getattr(target_profile, "websocket_detected", False)
            ),
            "jwt_detected": bool(
                getattr(target_profile, "jwt_detected", False)
            ),
            "llm_detected": bool(
                getattr(target_profile, "llm_detected", False)
            ),
            "payment_related": bool(
                getattr(target_profile, "payment_related", False)
            ),
            "webhook_present": bool(
                getattr(target_profile, "webhook_present", False)
            ),
        }

        active_indicators = {
            key: value
            for key, value in indicators.items()
            if value
        }

        if active_indicators:
            result.add_observation({
                "type": "specialized_indicators",
                "indicators": active_indicators,
            })

        security_headers = getattr(
            target_profile,
            "security_headers",
            {},
        ) or {}

        if security_headers:
            result.add_observation({
                "type": "security_headers",
                "headers": security_headers,
            })

        # ---------------------------------------------------------
        # Structured hypotheses
        # ---------------------------------------------------------

        if api_endpoints:
            result.add_hypothesis(self._make_hypothesis(
                agent=self.name,
                vulnerability_type="api_surface_review",
                target=target,
                description=(
                    "Reconnaissance identified API endpoints. These endpoints "
                    "should be reviewed for authentication, authorization, "
                    "input validation, and unintended data exposure."
                ),
                confidence=0.55,
                priority="high",
                metadata={
                    "endpoint_count": len(api_endpoints),
                    "endpoints": api_endpoints,
                },
            ))

        if authentication_present:
            result.add_hypothesis(self._make_hypothesis(
                agent=self.name,
                vulnerability_type="authentication_review",
                target=target,
                description=(
                    "Authentication-related endpoints were identified. "
                    "The authentication surface should be reviewed for "
                    "session handling, access controls, and authentication "
                    "workflow weaknesses."
                ),
                confidence=0.55,
                priority="high",
                metadata={
                    "endpoint_count": len(auth_endpoints),
                    "endpoints": auth_endpoints,
                },
            ))

        if authorization_relevant:
            result.add_hypothesis(self._make_hypothesis(
                agent=self.name,
                vulnerability_type="authorization_review",
                target=target,
                description=(
                    "Reconnaissance indicates that authorization is relevant "
                    "to the target. Resource and role boundaries should be "
                    "reviewed for unintended access."
                ),
                confidence=0.55,
                priority="high",
                metadata={
                    "endpoint_count": len(endpoints),
                },
            ))

        if admin_endpoints:
            result.add_hypothesis(self._make_hypothesis(
                agent=self.name,
                vulnerability_type="admin_surface_review",
                target=target,
                description=(
                    "Administrative endpoints were discovered. Their "
                    "authentication and authorization boundaries should "
                    "be reviewed."
                ),
                confidence=0.50,
                priority="high",
                metadata={
                    "endpoint_count": len(admin_endpoints),
                    "endpoints": admin_endpoints,
                },
            ))

        if upload_endpoints:
            result.add_hypothesis(self._make_hypothesis(
                agent=self.name,
                vulnerability_type="file_upload_review",
                target=target,
                description=(
                    "File upload endpoints were discovered. File type "
                    "validation, storage behavior, access controls, and "
                    "content handling should be reviewed."
                ),
                confidence=0.50,
                priority="medium",
                metadata={
                    "endpoint_count": len(upload_endpoints),
                    "endpoints": upload_endpoints,
                },
            ))

        if download_endpoints:
            result.add_hypothesis(self._make_hypothesis(
                agent=self.name,
                vulnerability_type="file_download_review",
                target=target,
                description=(
                    "File download endpoints were discovered. Resource "
                    "authorization and unintended file exposure should "
                    "be reviewed."
                ),
                confidence=0.50,
                priority="medium",
                metadata={
                    "endpoint_count": len(download_endpoints),
                    "endpoints": download_endpoints,
                },
            ))

        if indicators["websocket_detected"]:
            result.add_hypothesis(self._make_hypothesis(
                agent=self.name,
                vulnerability_type="websocket_review",
                target=target,
                description=(
                    "WebSocket indicators were detected. Connection "
                    "authentication, authorization, and message handling "
                    "should be reviewed."
                ),
                confidence=0.45,
                priority="medium",
            ))

        if indicators["jwt_detected"]:
            result.add_hypothesis(self._make_hypothesis(
                agent=self.name,
                vulnerability_type="jwt_review",
                target=target,
                description=(
                    "JWT indicators were detected. Token validation, "
                    "claims, expiration, signing configuration, and "
                    "authorization behavior should be reviewed."
                ),
                confidence=0.45,
                priority="medium",
            ))

        if indicators["llm_detected"]:
            result.add_hypothesis(self._make_hypothesis(
                agent=self.name,
                vulnerability_type="llm_review",
                target=target,
                description=(
                    "LLM-related functionality was detected. Inputs, "
                    "outputs, authorization boundaries, data exposure, "
                    "and prompt-handling behavior should be reviewed."
                ),
                confidence=0.45,
                priority="medium",
            ))

        result.metadata["hypothesis_count"] = len(result.hypotheses)
        result.metadata["observation_count"] = len(result.observations)

        return result

    @staticmethod
    def _make_hypothesis(
        agent: str,
        vulnerability_type: str,
        target: str,
        description: str,
        confidence: float,
        priority: str,
        metadata: dict[str, Any] | None = None,
    ) -> Hypothesis:
        return Hypothesis(
            id=f"{agent}-{uuid4().hex[:12]}",
            agent=agent,
            vulnerability_type=vulnerability_type,
            target=target,
            description=description,
            confidence=max(0.0, min(1.0, confidence)),
            priority=priority,
            status="pending",
            metadata=metadata or {},
        )

    @staticmethod
    def _get_target(
        scan_result: Any,
        target_profile: Any,
    ) -> str:
        target = getattr(scan_result, "target", None)

        if target:
            return str(target)

        target = getattr(target_profile, "target", None)

        if target:
            return str(target)

        return "unknown"

    @staticmethod
    def _get_list(
        target_profile: Any,
        attribute: str,
    ) -> list:
        if target_profile is None:
            return []

        value = getattr(target_profile, attribute, None)

        if value is None:
            return []

        if isinstance(value, list):
            return value

        try:
            return list(value)
        except TypeError:
            return []
