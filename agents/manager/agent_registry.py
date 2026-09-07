from __future__ import annotations

from typing import Type

from agents.base_agent import BaseSecurityAgent

from agents.security.app_review_agent import AppReviewAgent
from agents.security.api_agent import ApiAgent
from agents.security.auth_agent import AuthAgent
from agents.security.idor_agent import IdorAgent
from agents.security.xss_agent import XssAgent


class AgentRegistry:
    """
    Central registry for BugHunter security agents.

    The registry maps stable agent names to their Python
    implementation classes.
    """

    def __init__(self) -> None:
        self._agents: dict[str, Type[BaseSecurityAgent]] = {
            "app_review": AppReviewAgent,
            "api": ApiAgent,
            "auth": AuthAgent,
            "idor": IdorAgent,
            "xss": XssAgent,
        }

    def register(
        self,
        name: str,
        agent_class: Type[BaseSecurityAgent],
    ) -> None:
        if not name:
            raise ValueError("Agent name cannot be empty.")

        if not issubclass(agent_class, BaseSecurityAgent):
            raise TypeError(
                f"{agent_class.__name__} must inherit from "
                "BaseSecurityAgent."
            )

        self._agents[name] = agent_class

    def get_class(
        self,
        name: str,
    ) -> Type[BaseSecurityAgent] | None:
        return self._agents.get(name)

    def create(
        self,
        name: str,
    ) -> BaseSecurityAgent:
        agent_class = self.get_class(name)

        if agent_class is None:
            raise KeyError(
                f"Security agent '{name}' is not registered."
            )

        return agent_class()

    def has(self, name: str) -> bool:
        return name in self._agents

    def names(self) -> list[str]:
        return sorted(self._agents.keys())

    def missing(self, names: list[str]) -> list[str]:
        return [
            name
            for name in names
            if not self.has(name)
        ]
