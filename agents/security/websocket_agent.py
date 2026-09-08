from __future__ import annotations

from typing import Any
from uuid import uuid4

from agents.base_agent import BaseSecurityAgent
from models.agent_result import AgentResult
from models.hypothesis import Hypothesis


class WebsocketAgent(BaseSecurityAgent):
    name = "websocket"
    description = (
        "Analyzes discovered WebSocket functionality and real-time "
        "communication surfaces."
    )

    def run(
        self,
        scan_result: Any,
        target_profile: Any,
        context: dict[str, Any] | None = None,
    ) -> AgentResult:

        target = (
            getattr(scan_result, "target", None)
            or getattr(target_profile, "target", None)
            or "unknown"
        )

        result = AgentResult(
            agent=self.name,
            target=target,
            metadata={
                "phase": 3,
                "implemented": True,
                "analysis_type": "recon_driven",
                "destructive_testing": False,
            },
        )

        detected = bool(
            getattr(target_profile, "websocket_detected", False)
        )

        websocket_surfaces: list[Any] = []

        if detected:
            websocket_surfaces.append(target)

            result.add_observation(
                {
                    "type": "websocket_surface",
                    "source_url": target,
                    "message": (
                        "WebSocket functionality was detected during "
                        "reconnaissance."
                    ),
                    "severity": "medium",
                    "confidence": 0.90,
                }
            )

        for item in getattr(scan_result, "urls", []) or []:
            url = getattr(item, "url", None)

            if not url:
                continue

            lowered = url.lower()

            if (
                lowered.startswith("ws://")
                or lowered.startswith("wss://")
                or "websocket" in lowered
            ):
                if url not in websocket_surfaces:
                    websocket_surfaces.append(url)

                result.add_observation(
                    {
                        "type": "websocket_endpoint",
                        "source_url": url,
                        "message": (
                            "A potential WebSocket endpoint was identified "
                            "in the available reconnaissance data."
                        ),
                        "severity": "medium",
                        "confidence": 0.75,
                    }
                )

        result.add_observation(
            {
                "type": "websocket_surface_summary",
                "source_url": target,
                "surface_count": len(websocket_surfaces),
                "message": (
                    f"{len(websocket_surfaces)} WebSocket surface(s) "
                    "were identified."
                ),
                "severity": "info",
                "confidence": 0.90,
            }
        )

        if websocket_surfaces:
            hypotheses = [
                (
                    "websocket_authentication",
                    "Review authentication requirements for WebSocket connections.",
                    "high",
                ),
                (
                    "websocket_authorization",
                    "Review authorization boundaries for WebSocket messages and channels.",
                    "high",
                ),
                (
                    "websocket_message_validation",
                    "Review validation and handling of WebSocket message data.",
                    "medium",
                ),
                (
                    "websocket_origin_policy",
                    "Review origin and cross-origin controls for WebSocket connections.",
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
                    confidence=0.70,
                    priority=priority,
                    status="pending",
                    metadata={
                        "phase": 3,
                        "websocket_surfaces": websocket_surfaces,
                    },
                )

                result.add_hypothesis(hypothesis)

        result.metadata.update(
            {
                "websocket_detected": detected,
                "surface_count": len(websocket_surfaces),
                "hypothesis_count": len(result.hypotheses),
                "observation_count": len(result.observations),
            }
        )

        return result