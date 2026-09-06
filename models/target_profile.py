from models.scan_result import ScanResult
from models.target_profile import TargetProfile


class TargetProfiler:
    """
    Converts ReconAgent ScanResult data into a TargetProfile.

    The profiler identifies attack surfaces and application features.
    It does not determine whether a vulnerability exists.
    """

    def build(self, scan: ScanResult) -> TargetProfile:

        profile = TargetProfile(
            target=scan.target,
            technologies=list(scan.technologies)
        )

        # =========================================================
        # Hosts
        # =========================================================

        profile.hosts = [
            host.host
            for host in scan.hosts
            if getattr(host, "host", "")
        ]

        # Determine live hosts where status information is available.
        profile.live_hosts = []

        for host in scan.hosts:

            host_value = getattr(host, "host", "")

            if not host_value:
                continue

            status = getattr(host, "status", 0)

            try:
                if int(status) > 0:
                    profile.live_hosts.append(host_value)
            except (TypeError, ValueError):
                pass

        # =========================================================
        # URLs / Endpoints
        # =========================================================

        profile.endpoints = [
            url.url
            for url in scan.urls
            if getattr(url, "url", "")
        ]

        # =========================================================
        # URL Categories
        # =========================================================

        for category in scan.url_categories:

            category_name = str(
                category.category
            ).lower()

            url = category.url

            if not url:
                continue

            # API
            if any(
                value in category_name
                for value in (
                    "api",
                    "rest"
                )
            ):
                self._add_unique(
                    profile.api_endpoints,
                    url
                )

            # Authentication
            if any(
                value in category_name
                for value in (
                    "auth",
                    "login",
                    "signin",
                    "sign-in",
                    "register",
                    "signup",
                    "sign-up"
                )
            ):
                self._add_unique(
                    profile.auth_endpoints,
                    url
                )

            # Admin
            if any(
                value in category_name
                for value in (
                    "admin",
                    "administrator",
                    "management"
                )
            ):
                self._add_unique(
                    profile.admin_endpoints,
                    url
                )

            # Upload
            if any(
                value in category_name
                for value in (
                    "upload",
                    "file_upload",
                    "file-upload"
                )
            ):
                self._add_unique(
                    profile.upload_endpoints,
                    url
                )

            # Download
            if any(
                value in category_name
                for value in (
                    "download",
                    "export"
                )
            ):
                self._add_unique(
                    profile.download_endpoints,
                    url
                )

            # Dashboard
            if any(
                value in category_name
                for value in (
                    "dashboard",
                    "panel",
                    "portal"
                )
            ):
                self._add_unique(
                    profile.dashboard_endpoints,
                    url
                )

        # =========================================================
        # Authentication
        # =========================================================

        profile.authentication_present = bool(
            profile.auth_endpoints
        )

        # =========================================================
        # Authorization
        # =========================================================

        profile.authorization_relevant = bool(
            profile.admin_endpoints
            or profile.dashboard_endpoints
            or profile.api_endpoints
        )

        # =========================================================
        # File Uploads
        # =========================================================

        profile.file_upload_present = bool(
            profile.upload_endpoints
        )

        # =========================================================
        # JavaScript Findings
        # =========================================================

        profile.javascript_findings = list(
            scan.javascript_findings
        )

        # =========================================================
        # JWT
        # =========================================================

        profile.jwt_results = list(
            scan.jwt_results
        )

        profile.jwt_detected = bool(
            scan.jwt_results
        )

        # =========================================================
        # Technology / Protocol Detection
        # =========================================================

        technology_text = " ".join(
            str(technology).lower()
            for technology in scan.technologies
        )

        endpoint_text = " ".join(
            profile.endpoints
        ).lower()

        # GraphQL
        profile.graphql_detected = (
            "graphql" in technology_text
            or "graphql" in endpoint_text
        )

        # WebSocket
        profile.websocket_detected = (
            "websocket" in technology_text
            or "ws://" in endpoint_text
            or "wss://" in endpoint_text
        )

        # Also inspect JavaScript findings.
        for finding in scan.javascript_findings:

            finding_type = str(
                getattr(
                    finding,
                    "type",
                    ""
                )
            ).lower()

            finding_value = str(
                getattr(
                    finding,
                    "value",
                    ""
                )
            ).lower()

            javascript_text = (
                finding_type
                + " "
                + finding_value
            )

            if "graphql" in javascript_text:
                profile.graphql_detected = True

            if any(
                value in javascript_text
                for value in (
                    "websocket",
                    "ws://",
                    "wss://"
                )
            ):
                profile.websocket_detected = True

        # =========================================================
        # LLM Detection
        # =========================================================

        profile.llm_detected = any(
            indicator in technology_text
            or indicator in endpoint_text
            for indicator in (
                "openai",
                "chatgpt",
                "gemini",
                "anthropic",
                "claude",
                "llm",
                "vertex ai"
            )
        )

        # =========================================================
        # Payment Detection
        # =========================================================

        profile.payment_related = any(
            indicator in endpoint_text
            for indicator in (
                "payment",
                "payments",
                "checkout",
                "billing",
                "invoice",
                "subscription",
                "order"
            )
        )

        # =========================================================
        # Webhook Detection
        # =========================================================

        profile.webhook_present = any(
            indicator in endpoint_text
            for indicator in (
                "webhook",
                "webhooks",
                "callback",
                "callbacks"
            )
        )

        # =========================================================
        # Security Headers
        # =========================================================

        profile.security_headers = {}

        for header_result in scan.header_results:

            host = getattr(
                header_result,
                "host",
                ""
            )

            headers = getattr(
                header_result,
                "headers",
                {}
            )

            if host:
                profile.security_headers[host] = headers

        # =========================================================
        # TLS
        # =========================================================

        profile.tls_information = list(
            scan.tls_results
        )

        # =========================================================
        # HTTP Methods
        # =========================================================

        profile.http_methods = list(
            scan.http_methods
        )

        return profile

    # =============================================================
    # Helpers
    # =============================================================

    @staticmethod
    def _add_unique(
        collection: list,
        value: str
    ):
        """
        Add an item without creating duplicates.
        """

        if value and value not in collection:
            collection.append(value)