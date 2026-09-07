from models.scan_result import ScanResult
from models.target_profile import TargetProfile


class TargetProfiler:
    """
    Converts ReconAgent ScanResult data into a TargetProfile.

    The profiler identifies application attack surfaces and technologies.
    It does NOT determine whether a vulnerability exists.
    """

    name = "target_profiler"

    def __init__(self):
        self.name = "target_profiler"

    def build(self, scan: ScanResult) -> TargetProfile:
        """Build a TargetProfile from a ReconAgent ScanResult."""
        return self.build_profile(scan)



    def build_profile(self, scan: ScanResult) -> TargetProfile:

        if not isinstance(scan, ScanResult):
            raise TypeError(
                "TargetProfiler requires a ScanResult object."
            )

        profile = TargetProfile(
            target=scan.target
        )

        # ---------------------------------------------------------
        # Infrastructure
        # ---------------------------------------------------------

        profile.technologies = list(scan.technologies)

        profile.hosts = [
            self._get_host_value(host)
            for host in scan.hosts
            if self._get_host_value(host)
        ]

        profile.live_hosts = [
            self._get_live_host_value(host)
            for host in scan.hosts
            if self._is_live_host(host)
        ]

        # ---------------------------------------------------------
        # URLs / Endpoints
        # ---------------------------------------------------------

        profile.endpoints = [
            self._get_url_value(url)
            for url in scan.urls
            if self._get_url_value(url)
        ]

        # ---------------------------------------------------------
        # URL Categories
        # ---------------------------------------------------------

        for category in scan.url_categories:

            url = getattr(category, "url", "")
            category_name = getattr(
                category,
                "category",
                ""
            )

            if not url:
                continue

            category_name = category_name.lower()

            if self._contains_any(
                category_name,
                ["api", "rest", "graphql"]
            ):
                self._add_unique(
                    profile.api_endpoints,
                    url
                )

            if self._contains_any(
                category_name,
                [
                    "auth",
                    "login",
                    "signin",
                    "sign-in",
                    "register",
                    "signup",
                    "sign-up",
                    "password"
                ]
            ):
                self._add_unique(
                    profile.auth_endpoints,
                    url
                )

            if self._contains_any(
                category_name,
                [
                    "admin",
                    "administrator",
                    "management"
                ]
            ):
                self._add_unique(
                    profile.admin_endpoints,
                    url
                )

            if self._contains_any(
                category_name,
                [
                    "upload",
                    "file-upload",
                    "file_upload"
                ]
            ):
                self._add_unique(
                    profile.upload_endpoints,
                    url
                )

            if self._contains_any(
                category_name,
                [
                    "download",
                    "export"
                ]
            ):
                self._add_unique(
                    profile.download_endpoints,
                    url
                )

            if self._contains_any(
                category_name,
                [
                    "dashboard",
                    "panel",
                    "portal"
                ]
            ):
                self._add_unique(
                    profile.dashboard_endpoints,
                    url
                )

        # ---------------------------------------------------------
        # Technology / Protocol Detection
        # ---------------------------------------------------------

        technology_text = " ".join(
            str(item).lower()
            for item in scan.technologies
        )

        endpoint_text = " ".join(
            profile.endpoints
        ).lower()

        javascript_text = " ".join(
            str(getattr(item, "value", ""))
            for item in scan.javascript_findings
        ).lower()

        combined_text = (
            technology_text
            + " "
            + endpoint_text
            + " "
            + javascript_text
        )

        profile.graphql_detected = (
            "graphql" in combined_text
            or any(
                "/graphql" in endpoint.lower()
                for endpoint in profile.endpoints
            )
        )

        profile.websocket_detected = (
            "websocket" in combined_text
            or "wss://" in endpoint_text
            or "ws://" in endpoint_text
        )

        profile.jwt_detected = bool(
            scan.jwt_results
        ) or "jwt" in combined_text

        profile.llm_detected = self._detect_llm(
            combined_text
        )

        # ---------------------------------------------------------
        # Application Features
        # ---------------------------------------------------------

        profile.authentication_present = (
            bool(profile.auth_endpoints)
            or profile.jwt_detected
            or self._detect_authentication(
                profile.endpoints,
                combined_text
            )
        )

        profile.authorization_relevant = (
            bool(profile.admin_endpoints)
            or bool(profile.dashboard_endpoints)
            or bool(profile.api_endpoints)
            or self._detect_identifier_patterns(
                profile.endpoints
            )
        )

        profile.file_upload_present = (
            bool(profile.upload_endpoints)
            or self._detect_file_upload(
                profile.endpoints,
                combined_text
            )
        )

        profile.payment_related = self._detect_feature(
            profile.endpoints,
            [
                "payment",
                "payments",
                "checkout",
                "billing",
                "invoice",
                "subscription",
                "order"
            ]
        )

        profile.webhook_present = self._detect_feature(
            profile.endpoints,
            [
                "webhook",
                "webhooks",
                "callback",
                "callbacks"
            ]
        )

        # ---------------------------------------------------------
        # Security Information
        # ---------------------------------------------------------

        profile.security_headers = self._build_header_profile(
            scan
        )

        profile.tls_information = list(
            scan.tls_results
        )

        profile.http_methods = list(
            scan.http_methods
        )

        # ---------------------------------------------------------
        # Recon Findings
        # ---------------------------------------------------------

        profile.javascript_findings = list(
            scan.javascript_findings
        )

        profile.jwt_results = list(
            scan.jwt_results
        )

        return profile

    # =============================================================
    # Helper Methods
    # =============================================================

    @staticmethod
    def _add_unique(items: list, value):
        """
        Add a value without creating duplicates.
        """

        if value and value not in items:
            items.append(value)

    @staticmethod
    def _contains_any(
        text: str,
        values: list[str]
    ) -> bool:

        return any(
            value in text
            for value in values
        )

    @staticmethod
    def _get_url_value(url_result) -> str:
        """
        Extract URL from UrlResult.
        """

        return str(
            getattr(url_result, "url", "")
        )

    @staticmethod
    def _get_host_value(host_result) -> str:
        """
        Extract host value from HostResult.

        Supports common field names without requiring
        changes to HostResult.
        """

        for field in (
            "host",
            "hostname",
            "domain"
        ):
            value = getattr(
                host_result,
                field,
                ""
            )

            if value:
                return str(value)

        return ""

    @staticmethod
    def _get_live_host_value(host_result) -> str:
        """
        Extract the best host representation from a live host.
        """

        for field in (
            "url",
            "host",
            "hostname",
            "domain"
        ):
            value = getattr(
                host_result,
                field,
                ""
            )

            if value:
                return str(value)

        return ""

    @staticmethod
    def _is_live_host(host_result) -> bool:
        """
        Determine whether a host is live.
        """

        for field in (
            "live",
            "is_live",
            "alive"
        ):
            value = getattr(
                host_result,
                field,
                None
            )

            if value is not None:
                return bool(value)

        # If HostResult doesn't have an explicit live flag,
        # use common HTTP status indicators.
        status = getattr(
            host_result,
            "status",
            0
        )

        try:
            return int(status) > 0
        except (TypeError, ValueError):
            return False

    @staticmethod
    def _detect_llm(text: str) -> bool:

        indicators = [
            "openai",
            "chatgpt",
            "gemini",
            "google ai",
            "vertex ai",
            "anthropic",
            "claude",
            "llm",
            "large language model",
            "generative ai",
            "generative-ai"
        ]

        return any(
            indicator in text
            for indicator in indicators
        )

    @staticmethod
    def _detect_authentication(
        endpoints: list[str],
        text: str
    ) -> bool:

        auth_terms = [
            "login",
            "signin",
            "sign-in",
            "register",
            "signup",
            "sign-up",
            "authenticate",
            "authentication",
            "oauth",
            "authorize",
            "password",
            "session",
            "token"
        ]

        endpoint_text = " ".join(
            endpoints
        ).lower()

        return any(
            term in endpoint_text
            or term in text
            for term in auth_terms
        )

    @staticmethod
    def _detect_file_upload(
        endpoints: list[str],
        text: str
    ) -> bool:

        upload_terms = [
            "upload",
            "file",
            "attachment",
            "multipart",
            "media"
        ]

        endpoint_text = " ".join(
            endpoints
        ).lower()

        combined = endpoint_text + " " + text

        return any(
            term in combined
            for term in upload_terms
        )

    @staticmethod
    def _detect_feature(
        endpoints: list[str],
        terms: list[str]
    ) -> bool:

        endpoint_text = " ".join(
            endpoints
        ).lower()

        return any(
            term in endpoint_text
            for term in terms
        )

    @staticmethod
    def _detect_identifier_patterns(
        endpoints: list[str]
    ) -> bool:

        patterns = [
            "/user/",
            "/users/",
            "/account/",
            "/accounts/",
            "/profile/",
            "/profiles/",
            "/customer/",
            "/customers/",
            "/order/",
            "/orders/",
            "/invoice/",
            "/invoices/",
            "/document/",
            "/documents/",
            "/file/",
            "/files/",
            "/id/",
            "?id=",
            "?user_id=",
            "?account_id="
        ]

        endpoint_text = " ".join(
            endpoints
        ).lower()

        return any(
            pattern in endpoint_text
            for pattern in patterns
        )

    @staticmethod
    def _build_header_profile(
        scan: ScanResult
    ) -> dict:

        headers = {}

        for result in scan.header_results:

            host = getattr(
                result,
                "host",
                ""
            )

            values = {}

            # Support either a dictionary field or
            # individual header attributes.
            raw_headers = getattr(
                result,
                "headers",
                None
            )

            if isinstance(raw_headers, dict):
                values = raw_headers

            if host:
                headers[host] = values
            else:
                headers[str(
                    len(headers)
                )] = values

        return headers