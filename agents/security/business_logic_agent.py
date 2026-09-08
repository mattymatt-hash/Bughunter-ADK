from __future__ import annotations

from typing import Any
from uuid import uuid4

from agents.base_agent import BaseSecurityAgent
from models.agent_result import AgentResult
from models.hypothesis import Hypothesis


class BusinessLogicAgent(BaseSecurityAgent):
    name = "business_logic"
    description = (
        "Analyzes transaction, payment, workflow, and business-process "
        "surfaces for potential business logic weaknesses."
    )

    BUSINESS_INDICATORS = (
        "/checkout",
        "/cart",
        "/order",
        "/orders",
        "/purchase",
        "/payment",
        "/payments",
        "/invoice",
        "/invoices",
        "/subscription",
        "/subscriptions",
        "/transfer",
        "/refund",
        "/coupon",
        "/discount",
        "/redeem",
        "/balance",
        "/transaction",
        "/transactions",
        "/webhook",
        "/billing",
    )

    PARAMETER_INDICATORS = {
        "amount",
        "price",
        "quantity",
        "discount",
        "coupon",
        "total",
        "payment",
        "product",
        "item",
        "order",
        "transaction",
        "balance",
        "role",
        "status",
    }

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

        surfaces: list[dict[str, Any]] = []

        if getattr(target_profile, "payment_related", False):
            result.add_observation(
                {
                    "type": "payment_business_surface",
                    "source_url": target,
                    "message": (
                        "The target profile indicates payment-related "
                        "functionality."
                    ),
                    "severity": "medium",
                    "confidence": 0.90,
                }
            )

            surfaces.append(
                {
                    "type": "payment",
                    "source": "target_profile",
                    "target": target,
                }
            )

        if getattr(target_profile, "webhook_present", False):
            result.add_observation(
                {
                    "type": "webhook_business_surface",
                    "source_url": target,
                    "message": (
                        "The target profile indicates webhook-related "
                        "functionality."
                    ),
                    "severity": "medium",
                    "confidence": 0.90,
                }
            )

            surfaces.append(
                {
                    "type": "webhook",
                    "source": "target_profile",
                    "target": target,
                }
            )

        for url in self._get_urls(scan_result, target_profile):
            lowered = url.lower()

            matched_indicators = [
                indicator
                for indicator in self.BUSINESS_INDICATORS
                if indicator in lowered
            ]

            if matched_indicators:
                surfaces.append(
                    {
                        "type": "business_endpoint",
                        "url": url,
                        "indicators": matched_indicators,
                    }
                )

                result.add_observation(
                    {
                        "type": "business_logic_endpoint",
                        "source_url": url,
                        "indicators": matched_indicators,
                        "message": (
                            "An endpoint associated with transactional "
                            "or business workflow functionality was "
                            "identified."
                        ),
                        "severity": "medium",
                        "confidence": 0.75,
                    }
                )

        result.add_observation(
            {
                "type": "business_logic_surface",
                "source_url": target,
                "surface_count": len(surfaces),
                "message": (
                    f"{len(surfaces)} potential business-logic "
                    "surface(s) were identified."
                ),
                "severity": "info",
                "confidence": 0.90,
            }
        )

        if surfaces:
            hypotheses = [
                (
                    "business_logic_workflow",
                    "Review transactional workflows for logic and state-transition weaknesses.",
                    "high",
                ),
                (
                    "business_logic_parameter_trust",
                    "Review trust placed in client-controlled business parameters.",
                    "high",
                ),
                (
                    "business_logic_transaction_state",
                    "Review transaction and workflow state transitions.",
                    "medium",
                ),
                (
                    "business_logic_payment_flow",
                    "Review payment-related business rules and workflow boundaries.",
                    "high",
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
                        "surfaces": surfaces,
                    },
                )

                result.add_hypothesis(hypothesis)

        result.metadata.update(
            {
                "surface_count": len(surfaces),
                "hypothesis_count": len(result.hypotheses),
                "observation_count": len(result.observations),
            }
        )

        return result

    def _get_urls(
        self,
        scan_result: Any,
        target_profile: Any,
    ) -> list[str]:

        urls: list[str] = []

        for item in getattr(scan_result, "urls", []) or []:
            url = getattr(item, "url", None)

            if url and url not in urls:
                urls.append(url)

        for url in getattr(target_profile, "endpoints", []) or []:
            if url and url not in urls:
                urls.append(url)

        for url in getattr(target_profile, "api_endpoints", []) or []:
            if url and url not in urls:
                urls.append(url)

        return urls