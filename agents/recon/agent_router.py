class AgentRouter:

    def select(self, profile):

        selected = set()

        # Always
        selected.add("app_review")

        # Authentication
        if profile.authentication_present:
            selected.add("auth")

        # APIs
        if profile.api_endpoints:
            selected.add("api")
            selected.add("idor")

        # Admin functionality
        if profile.admin_endpoints:
            selected.add("idor")
            selected.add("business_logic")

        # Upload functionality
        if profile.file_upload_present:
            selected.add("file_upload")

        # GraphQL
        if profile.graphql_detected:
            selected.add("graphql")

        # WebSockets
        if profile.websocket_detected:
            selected.add("websocket")

        # JWT
        if profile.jwt_detected:
            selected.add("auth")

        # General web input analysis
        selected.update({
            "xss",
            "sqli",
            "ssrf",
            "csrf",
            "cors"
        })

        return sorted(selected)