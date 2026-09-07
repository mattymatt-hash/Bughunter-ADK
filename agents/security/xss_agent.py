from __future__ import annotations

from uuid import uuid4
from typing import Any

from agents.base_agent import BaseSecurityAgent
from models.agent_result import AgentResult
from models.hypothesis import Hypothesis


class XssAgent(BaseSecurityAgent):
    name = "xss"
    description = "Analyzes application input and JavaScript surfaces for XSS hypotheses."

    def run(
        self,
        scan_result: Any,
        target_profile: Any,
        context: dict[str, Any] | None = None,
    ) -> AgentResult:

        target = getattr(
            target_profile,
            "target",
            getattr(scan_result, "target", "unknown"),
        )

        result = AgentResult(
            agent=self.name,
            target=target,
        )

        endpoints = list(
            getattr(target_profile, "endpoints", []) or []
        )

        javascript_findings = list(
            getattr(target_profile, "javascript_findings", []) or []
        )

        result.observations.append({
            "type": "xss_surface",
            "endpoint_count": len(endpoints),
            "javascript_finding_count": len(javascript_findings),
        })

        if not endpoints and not javascript_findings:
            result.metadata.update({
                "phase": 1,
                "implemented": True,
                "analysis_type": "recon_driven",
                "hypothesis_count": 0,
            })

            return result

        hypotheses = [
            (
                "reflected_input_surface",
                "Review endpoint input parameters for reflected input/output paths.",
                "high",
            ),
            (
                "stored_input_surface",
                "Review application inputs that may be persisted and later rendered.",
                "high",
            ),
            (
                "dom_input_surface",
                "Review client-side input flows for DOM-based output handling.",
                "high",
            ),
            (
                "javascript_sink_surface",
                "Review discovered JavaScript findings for potentially dangerous output sinks.",
                "medium",
            ),
        ]

        for vulnerability_type, description, priority in hypotheses:
            hypothesis = Hypothesis(
                id=f"{self.name}-{uuid4().hex[:12]}",
                agent=self.name,
                vulnerability_type=vulnerability_type,
                target=target,
                description=description,
                confidence=0.60,
                priority=priority,
                status="pending",
                metadata={
                    "phase": 1,
                    "endpoint_count": len(endpoints),
                    "javascript_finding_count": len(javascript_findings),
                },
            )

            result.add_hypothesis(hypothesis)

        result.metadata.update({
            "phase": 1,
            "implemented": True,
            "analysis_type": "recon_driven",
            "destructive_testing": False,
            "hypothesis_count": len(result.hypotheses),
            "observation_count": len(result.observations),
        })

        return result
