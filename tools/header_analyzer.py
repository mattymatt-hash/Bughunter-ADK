from models.header_result import HeaderResult
from tools.retry import http


class HeaderAnalyzer:

    def analyze(self, url):

        result = HeaderResult(host=url)

        try:

            response = http.get(url)

            if response is None:
                return result

            if response.status_code >= 400:
                return result

        except Exception as e:

            result.error = str(e)

            return result

        headers = response.headers

        # -----------------------------------
        # Raw Header Values
        # -----------------------------------

        result.hsts_value = headers.get(
            "Strict-Transport-Security",
            "",
        )

        result.csp_value = headers.get(
            "Content-Security-Policy",
            "",
        )

        result.x_frame_options_value = headers.get(
            "X-Frame-Options",
            "",
        )

        result.x_content_type_options_value = headers.get(
            "X-Content-Type-Options",
            "",
        )

        result.referrer_policy_value = headers.get(
            "Referrer-Policy",
            "",
        )

        result.permissions_policy_value = headers.get(
            "Permissions-Policy",
            "",
        )

        # -----------------------------------
        # Presence
        # -----------------------------------

        result.hsts = bool(result.hsts_value)

        result.csp = bool(result.csp_value)

        result.x_frame_options = bool(
            result.x_frame_options_value
        )

        result.x_content_type_options = bool(
            result.x_content_type_options_value
        )

        result.referrer_policy = bool(
            result.referrer_policy_value
        )

        result.permissions_policy = bool(
            result.permissions_policy_value
        )

        # -----------------------------------
        # Additional Headers
        # -----------------------------------

        result.cross_origin_embedder_policy = headers.get(
            "Cross-Origin-Embedder-Policy",
            "",
        )

        result.cross_origin_opener_policy = headers.get(
            "Cross-Origin-Opener-Policy",
            "",
        )

        result.cross_origin_resource_policy = headers.get(
            "Cross-Origin-Resource-Policy",
            "",
        )

        result.origin_agent_cluster = headers.get(
            "Origin-Agent-Cluster",
            "",
        )

        result.clear_site_data = headers.get(
            "Clear-Site-Data",
            "",
        )

        # -----------------------------------
        # Misc
        # -----------------------------------

        result.cors = headers.get(
            "Access-Control-Allow-Origin",
            "",
        )

        result.server = headers.get(
            "Server",
            "",
        )

        result.powered_by = headers.get(
            "X-Powered-By",
            "",
        )

        result.content_type = headers.get(
            "Content-Type",
            "",
        )

        result.cache_control = headers.get(
            "Cache-Control",
            "",
        )

        result.etag = headers.get(
            "ETag",
            "",
        )

        result.date = headers.get(
            "Date",
            "",
        )

        result.content_length = headers.get(
            "Content-Length",
            "",
        )

        # -----------------------------------
        # Security Score
        # -----------------------------------

        score = 0

        if result.hsts:
            score += 1

        if result.csp:
            score += 1

        if result.x_frame_options:
            score += 1

        if result.x_content_type_options:
            score += 1

        if result.referrer_policy:
            score += 1

        if result.permissions_policy:
            score += 1

        result.security_score = score

        return result