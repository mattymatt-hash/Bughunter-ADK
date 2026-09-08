from __future__ import annotations

from typing import Type

from agents.base_agent import BaseSecurityAgent

# Phase 1
from agents.security.app_review_agent import AppReviewAgent
from agents.security.api_agent import ApiAgent
from agents.security.auth_agent import AuthAgent
from agents.security.idor_agent import IdorAgent
from agents.security.xss_agent import XssAgent

# Phase 2
from agents.security.sqli_agent import SqliAgent
from agents.security.ssrf_agent import SsrfAgent
from agents.security.csrf_agent import CsrfAgent
from agents.security.cors_agent import CorsAgent
from agents.security.admin_agent import AdminAgent

# Phase 3
from agents.security.business_logic_agent import BusinessLogicAgent
from agents.security.file_upload_agent import FileUploadAgent
from agents.security.websocket_agent import WebsocketAgent
from agents.security.llm_security_agent import LlmSecurityAgent


class AgentRegistry:
    def __init__(self):
        self._agents: dict[str, Type[BaseSecurityAgent]] = {
            # Phase 1
            "app_review": AppReviewAgent,
            "api": ApiAgent,
            "auth": AuthAgent,
            "idor": IdorAgent,
            "xss": XssAgent,

            # Phase 2
            "sqli": SqliAgent,
            "ssrf": SsrfAgent,
            "csrf": CsrfAgent,
            "cors": CorsAgent,
            "admin": AdminAgent,

            # Phase 3
            "business_logic": BusinessLogicAgent,
            "file_upload": FileUploadAgent,
            "websocket": WebsocketAgent,
            "llm_security": LlmSecurityAgent,
        }

    def register(
        self,
        name: str,
        agent_class: Type[BaseSecurityAgent],
    ):
        if not name:
            raise ValueError("Agent name cannot be empty.")

        if not issubclass(agent_class, BaseSecurityAgent):
            raise TypeError(
                "Registered agent must inherit from BaseSecurityAgent."
            )

        self._agents[name] = agent_class

    def get_class(self, name: str):
        return self._agents.get(name)

    def create(self, name: str):
        agent_class = self.get_class(name)

        if agent_class is None:
            raise KeyError(
                f"Agent '{name}' is not registered."
            )

        return agent_class()

    def has(self, name: str):
        return name in self._agents

    def names(self):
        return sorted(self._agents.keys())

    def missing(self, names):
        return [
            name
            for name in names
            if not self.has(name)
        ]