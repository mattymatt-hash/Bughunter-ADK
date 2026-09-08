from __future__ import annotations


class AgentRouter:
    PHASE_1_AGENTS = {
        "app_review",
        "api",
        "auth",
        "idor",
        "xss",
    }

    PHASE_2_AGENTS = {
        "sqli",
        "ssrf",
        "csrf",
        "cors",
        "admin",
    }

    PHASE_3_AGENTS = {
        "business_logic",
        "file_upload",
        "websocket",
        "llm_security",
    }

    def select(self, profile):
        selected = set()

        # -------------------------
        # Phase 1
        # -------------------------

        selected.add("app_review")
        selected.add("xss")

        if getattr(profile, "api_endpoints", []):
            selected.add("api")

        if getattr(profile, "authentication_present", False):
            selected.add("auth")

        if (
            getattr(profile, "authorization_relevant", False)
            and (
                getattr(profile, "api_endpoints", [])
                or getattr(profile, "endpoints", [])
            )
        ):
            selected.add("idor")

        # -------------------------
        # Phase 2
        # -------------------------

        endpoints = getattr(profile, "endpoints", []) or []
        api_endpoints = getattr(profile, "api_endpoints", []) or []
        auth_endpoints = getattr(profile, "auth_endpoints", []) or []
        admin_endpoints = getattr(profile, "admin_endpoints", []) or []
        dashboard_endpoints = (
            getattr(profile, "dashboard_endpoints", []) or []
        )

        if endpoints or api_endpoints:
            selected.add("sqli")
            selected.add("ssrf")

        if auth_endpoints or getattr(
            profile,
            "authentication_present",
            False,
        ):
            selected.add("csrf")

        # CORS review is useful for HTTP applications even when
        # explicit CORS headers were not discovered.
        selected.add("cors")

        if admin_endpoints or dashboard_endpoints:
            selected.add("admin")

        # -------------------------
        # Phase 3
        # -------------------------

        if (
            getattr(profile, "payment_related", False)
            or getattr(profile, "webhook_present", False)
        ):
            selected.add("business_logic")

        if (
            getattr(profile, "file_upload_present", False)
            or getattr(profile, "upload_endpoints", [])
        ):
            selected.add("file_upload")

        if getattr(profile, "websocket_detected", False):
            selected.add("websocket")

        if getattr(profile, "llm_detected", False):
            selected.add("llm_security")

        return sorted(selected)

    def is_phase_1_agent(self, agent_name):
        return agent_name in self.PHASE_1_AGENTS

    def is_phase_2_agent(self, agent_name):
        return agent_name in self.PHASE_2_AGENTS

    def is_phase_3_agent(self, agent_name):
        return agent_name in self.PHASE_3_AGENTS

    def available_agents(self):
        return sorted(
            self.PHASE_1_AGENTS
            | self.PHASE_2_AGENTS
            | self.PHASE_3_AGENTS
        )