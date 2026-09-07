from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from models.agent_result import AgentResult


class BaseSecurityAgent(ABC):
    """
    Common interface for all BugHunter security agents.

    Every specialized security agent receives the current
    ScanResult and TargetProfile and returns an AgentResult.
    """

    name: str = "base"
    description: str = ""

    def __init__(self) -> None:
        self.name = getattr(self.__class__, "name", self.name)
        self.description = getattr(
            self.__class__,
            "description",
            self.description,
        )

    @abstractmethod
    def run(
        self,
        scan_result: Any,
        target_profile: Any,
        context: dict[str, Any] | None = None,
    ) -> AgentResult:
        """
        Execute the agent against the supplied reconnaissance data.

        Agents should perform authorized, non-destructive security
        analysis and return structured results.
        """
        raise NotImplementedError
