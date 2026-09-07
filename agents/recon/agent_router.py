from __future__ import annotations

from typing import Any


class AgentRouter:
    """
    Selects security agents based on the TargetProfile.

    This class is the single source of truth for deciding which
    specialized security agents are relevant to a target.
    """

    PHASE_1_AGENTS = {
        "app_review",
        "api",
        "auth",
        "idor",
        "xss",
    }

    def select(self, profile: Any) -> list[str]:
        """
        Return the Phase 1 agents applicable to the target profile.
        """

        selected: set[str] = set()

        # Every target receives a general application review.
        selected.add("app_review")

        # API analysis is relevant when API endpoints exist.
        if getattr(profile, "api_endpoints", []):
            selected.add("api")

        # Authentication analysis.
        if getattr(profile, "authentication_present", False):
            selected.add("auth")

        # IDOR / authorization analysis.
        if (
            getattr(profile, "authorization_relevant", False)
            and (
                getattr(profile, "api_endpoints", [])
                or getattr(profile, "endpoints", [])
            )
        ):
            selected.add("idor")

        # XSS is currently part of the Phase 1 baseline.
        selected.add("xss")

        return sorted(selected)

    def is_phase_1_agent(self, agent_name: str) -> bool:
        """Return True when the agent belongs to Phase 1."""

        return agent_name in self.PHASE_1_AGENTS

    def available_agents(self) -> list[str]:
        """Return all Phase 1 agent names."""

        return sorted(self.PHASE_1_AGENTS)
