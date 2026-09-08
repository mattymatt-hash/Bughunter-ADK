from __future__ import annotations

from typing import Any
from uuid import uuid4
from urllib.parse import urlparse

from agents.base_agent import BaseSecurityAgent
from models.agent_result import AgentResult
from models.hypothesis import Hypothesis
from models.security_rating import observation_severity


class AppReviewAgent(BaseSecurityAgent):
    """
    Phase 1 application review agent.

    Performs non-destructive analysis of reconnaissance data and
    identifies application-surface areas that deserve further review.
    """

    name = "app_review"

    description = (
        "Reviews the discovered application surface, URLs, technologies, "
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

        # ---------------------------------------------------------
        # Target profile data
        # ---------------------------------------------------------

        endpoints = self._get_list(
            target_profile,
            "endpoints",
        )

        technologies = self._get_list(
            target_profile,
            "technologies",
        )

        api_endpoints = self._get_list(
            target_profile,
            "api_endpoints",
        )

        auth_endpoints = self._get_list(
            target_profile,
            "auth_endpoints",
        )

        admin_endpoints = self._get_list(
            target_profile,
            "admin_endpoints",
        )

        upload_endpoints = self._get_list(
            target_profile,
            "upload_endpoints",
        )

        download_endpoints = self._get_list(
            target_profile,
            "download_endpoints",
        )

        # ---------------------------------------------------------
        # Application surface summary
        # ---------------------------------------------------------

        result.add_observation({
            "type": "application_surface",
            "source_url": target,
            "endpoint_count": len(endpoints),
            "technology_count": len(technologies),
            "api_endpoint_count": len(api_endpoints),
            "auth_endpoint_count": len(auth_endpoints),
            "admin_endpoint_count": len(admin_endpoints),
            "upload_endpoint_count": len(upload_endpoints),
            "download_endpoint_count": len(download_endpoints),
            "severity": "info",
            "confidence": 0.95,
        })

        # ---------------------------------------------------------
        # Analyze every discovered URL
        # ---------------------------------------------------------

        urls = self._get_scan_urls(scan_result)

        for item in urls:
            url = self._get_url(item)

            if not url:
                continue

            status = self._get_status(item)

            parsed = urlparse(url)

            path = parsed.path or "/"
            query_present = bool(parsed.query)

            filename = path.rsplit("/", 1)[-1]

            extension = ""

            if "." in filename:
                extension = filename.rsplit(".", 1)[-1].lower()

            dynamic_extensions = {
                "php",
                "asp",
                "aspx",
                "jsp",
                "json",
                "cgi",
                "pl",
            }

            dynamic_indicator = (
                query_present
                or extension in dynamic_extensions
            )

            try:
                severity = observation_severity(
                    status=status,
                    has_query=query_present,
                )
            except Exception:
                severity = "info"

            result.add_observation({
                "type": "url_surface",
                "source_url": url,
                "message": (
                    "Discovered URL reviewed for application "
                    "attack-surface characteristics."
                ),
                "status": status,
                "path": path,
                "query_present": query_present,
                "dynamic_indicator": dynamic_indicator,
                "extension": extension,
                "severity": severity,
                "confidence": 0.95,
            })

            # -----------------------------------------------------
            # Query-string input surface
            # -----------------------------------------------------

            if query_present:
                result.add_observation({
                    "type": "query_input_surface",
                    "source_url": url,
                    "message": (
                        "URL contains query-string parameters that "
                        "represent a user-controlled input surface."
                    ),
                    "severity": "info",
                    "confidence": 0.95,
                })

                result.add_hypothesis(
                    self._make_hypothesis(
                        vulnerability_type="input_surface",
                        target=url,
                        title=(
                            "URL contains query parameters requiring "
                            "input review"
                        ),
                        description=(
                            f"The discovered URL exposes a query-string "
                            f"input surface that should be reviewed for "
                            f"input handling: {url}"
                        ),
                        confidence=0.55,
                        priority="medium",
                        metadata={
                            "source_url": url,
                            "query": parsed.query,
                        },
                    )
                )

        # ---------------------------------------------------------
        # Technology stack
        # ---------------------------------------------------------

        if technologies:
            result.add_observation({
                "type": "technology_stack",
                "source_url": target,
                "technologies": technologies,
                "severity": "info",
                "confidence": 0.90,
            })

        # ---------------------------------------------------------
        # Authentication
        # ---------------------------------------------------------

        authentication_present = bool(
            getattr(
                target_profile,
                "authentication_present",
                False,
            )
        )

        authorization_relevant = bool(
            getattr(
                target_profile,
                "authorization_relevant",
                False,
            )
        )

        if authentication_present:
            result.add_observation({
                "type": "authentication_surface",
                "source_url": (
                    auth_endpoints[0]
                    if auth_endpoints
                    else target
                ),
                "authentication_present": True,
                "endpoint_count": len(auth_endpoints),
                "endpoints": auth_endpoints,
                "severity": "info",
                "confidence": 0.95,
            })

        if authorization_relevant:
            result.add_observation({
                "type": "authorization_surface",
                "source_url": (
                    endpoints[0]
                    if endpoints
                    else target
                ),
                "authorization_relevant": True,
                "endpoint_count": len(endpoints),
                "severity": "info",
                "confidence": 0.90,
            })

        # ---------------------------------------------------------
        # API surface
        # ---------------------------------------------------------

        if api_endpoints:
            result.add_observation({
                "type": "api_surface",
                "source_url": api_endpoints[0],
                "endpoints": api_endpoints,
                "endpoint_count": len(api_endpoints),
                "severity": "info",
                "confidence": 0.95,
            })

        # ---------------------------------------------------------
        # Administrative surface
        # ---------------------------------------------------------

        if admin_endpoints:
            result.add_observation({
                "type": "administrative_surface",
                "source_url": admin_endpoints[0],
                "endpoints": admin_endpoints,
                "endpoint_count": len(admin_endpoints),
                "severity": "info",
                "confidence": 0.95,
            })

        # ---------------------------------------------------------
        # File upload surface
        # ---------------------------------------------------------

        if upload_endpoints:
            result.add_observation({
                "type": "file_upload_surface",
                "source_url": upload_endpoints[0],
                "endpoints": upload_endpoints,
                "endpoint_count": len(upload_endpoints),
                "severity": "info",
                "confidence": 0.95,
            })

        # ---------------------------------------------------------
        # File download surface
        # ---------------------------------------------------------

        if download_endpoints:
            result.add_observation({
                "type": "file_download_surface",
                "source_url": download_endpoints[0],
                "endpoints": download_endpoints,
                "endpoint_count": len(download_endpoints),
                "severity": "info",
                "confidence": 0.95,
            })

        # ---------------------------------------------------------
        # Specialized indicators
        # ---------------------------------------------------------

        indicators = {
            "graphql_detected": bool(
                getattr(
                    target_profile,
                    "graphql_detected",
                    False,
                )
            ),
            "websocket_detected": bool(
                getattr(
                    target_profile,
                    "websocket_detected",
                    False,
                )
            ),
            "jwt_detected": bool(
                getattr(
                    target_profile,
                    "jwt_detected",
                    False,
                )
            ),
            "llm_detected": bool(
                getattr(
                    target_profile,
                    "llm_detected",
                    False,
                )
            ),
            "payment_related": bool(
                getattr(
                    target_profile,
                    "payment_related",
                    False,
                )
            ),
            "webhook_present": bool(
                getattr(
                    target_profile,
                    "webhook_present",
                    False,
                )
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
                "source_url": target,
                "indicators": active_indicators,
                "severity": "info",
                "confidence": 0.85,
            })

        # ---------------------------------------------------------
        # Security headers
        # ---------------------------------------------------------

        security_headers = getattr(
            target_profile,
            "security_headers",
            {},
        ) or {}

        if security_headers:
            result.add_observation({
                "type": "security_headers",
                "source_url": target,
                "headers": security_headers,
                "severity": "info",
                "confidence": 0.95,
            })

        # ---------------------------------------------------------
        # Structured hypotheses
        # ---------------------------------------------------------

        if api_endpoints:
            result.add_hypothesis(
                self._make_hypothesis(
                    vulnerability_type="api_surface_review",
                    target=target,
                    title="API surface requires security review",
                    description=(
                        "Reconnaissance identified API endpoints. "
                        "These endpoints should be reviewed for "
                        "authentication, authorization, input validation, "
                        "and unintended data exposure."
                    ),
                    confidence=0.55,
                    priority="high",
                    metadata={
                        "endpoint_count": len(api_endpoints),
                        "endpoints": api_endpoints,
                    },
                )
            )

        if authentication_present:
            result.add_hypothesis(
                self._make_hypothesis(
                    vulnerability_type="authentication_review",
                    target=target,
                    title="Authentication surface requires review",
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
                )
            )

        if authorization_relevant:
            result.add_hypothesis(
                self._make_hypothesis(
                    vulnerability_type="authorization_review",
                    target=target,
                    title="Authorization surface requires review",
                    description=(
                        "Reconnaissance indicates that authorization is "
                        "relevant to the target. Resource and role boundaries "
                        "should be reviewed for unintended access."
                    ),
                    confidence=0.55,
                    priority="high",
                    metadata={
                        "endpoint_count": len(endpoints),
                    },
                )
            )

        if admin_endpoints:
            result.add_hypothesis(
                self._make_hypothesis(
                    vulnerability_type="admin_surface_review",
                    target=target,
                    title="Administrative surface requires review",
                    description=(
                        "Administrative endpoints were discovered. "
                        "Their authentication and authorization boundaries "
                        "should be reviewed."
                    ),
                    confidence=0.50,
                    priority="high",
                    metadata={
                        "endpoint_count": len(admin_endpoints),
                        "endpoints": admin_endpoints,
                    },
                )
            )

        if upload_endpoints:
            result.add_hypothesis(
                self._make_hypothesis(
                    vulnerability_type="file_upload_review",
                    target=target,
                    title="File upload surface requires review",
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
                )
            )

        if download_endpoints:
            result.add_hypothesis(
                self._make_hypothesis(
                    vulnerability_type="file_download_review",
                    target=target,
                    title="File download surface requires review",
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
                )
            )

        if indicators["websocket_detected"]:
            result.add_hypothesis(
                self._make_hypothesis(
                    vulnerability_type="websocket_review",
                    target=target,
                    title="WebSocket surface requires review",
                    description=(
                        "WebSocket indicators were detected. Connection "
                        "authentication, authorization, and message "
                        "handling should be reviewed."
                    ),
                    confidence=0.45,
                    priority="medium",
                )
            )

        if indicators["jwt_detected"]:
            result.add_hypothesis(
                self._make_hypothesis(
                    vulnerability_type="jwt_review",
                    target=target,
                    title="JWT implementation requires review",
                    description=(
                        "JWT indicators were detected. Token validation, "
                        "claims, expiration, signing configuration, and "
                        "authorization behavior should be reviewed."
                    ),
                    confidence=0.45,
                    priority="medium",
                )
            )

        if indicators["llm_detected"]:
            result.add_hypothesis(
                self._make_hypothesis(
                    vulnerability_type="llm_review",
                    target=target,
                    title="LLM functionality requires security review",
                    description=(
                        "LLM-related functionality was detected. Inputs, "
                        "outputs, authorization boundaries, data exposure, "
                        "and prompt-handling behavior should be reviewed."
                    ),
                    confidence=0.45,
                    priority="medium",
                )
            )

        # ---------------------------------------------------------
        # Final metadata
        # ---------------------------------------------------------

        result.metadata.update({
            "url_count": len(urls),
            "hypothesis_count": len(result.hypotheses),
            "observation_count": len(result.observations),
        })

        return result

    # =============================================================
    # Helpers
    # =============================================================

    @staticmethod
    def _make_hypothesis(
        vulnerability_type: str,
        target: str,
        title: str,
        description: str,
        confidence: float,
        priority: str,
        metadata: dict[str, Any] | None = None,
    ) -> Hypothesis:

        return Hypothesis(
            id=f"app-review-{uuid4().hex[:12]}",
            agent="app_review",
            vulnerability_type=vulnerability_type,
            title=title,
            target=target,
            description=description,
            confidence=max(
                0.0,
                min(1.0, confidence),
            ),
            priority=priority,
            status="pending",
            metadata=metadata or {},
        )

    @staticmethod
    def _get_target(
        scan_result: Any,
        target_profile: Any,
    ) -> str:

        target = getattr(
            scan_result,
            "target",
            None,
        )

        if target:
            return str(target)

        target = getattr(
            target_profile,
            "target",
            None,
        )

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

        value = getattr(
            target_profile,
            attribute,
            None,
        )

        if value is None:
            return []

        if isinstance(value, list):
            return value

        try:
            return list(value)
        except TypeError:
            return []

    @staticmethod
    def _get_scan_urls(
        scan_result: Any,
    ) -> list:

        if scan_result is None:
            return []

        urls = getattr(
            scan_result,
            "urls",
            None,
        )

        if urls is None:
            return []

        return list(urls)

    @staticmethod
    def _get_url(
        item: Any,
    ) -> str:

        if isinstance(item, dict):
            return str(
                item.get("url", "")
                or ""
            )

        return str(
            getattr(
                item,
                "url",
                "",
            )
            or ""
        )

    @staticmethod
    def _get_status(
        item: Any,
    ) -> int:

        if isinstance(item, dict):
            value = item.get("status", 0)
        else:
            value = getattr(
                item,
                "status",
                0,
            )

        try:
            return int(value or 0)
        except (TypeError, ValueError):
            return 0