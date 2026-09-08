from __future__ import annotations

import json
from typing import Any

from config.settings import GOOGLE_API_KEY, MODEL
from google import genai


class AIAnalyzer:
    """
    Reporting layer for BugHunter ADK.

    Uses structured reconnaissance and agent results to produce a concise
    security assessment without inventing vulnerabilities, endpoints,
    technologies, CVEs, or attack results.
    """

    def __init__(self):
        self.client = genai.Client(api_key=GOOGLE_API_KEY)
        self.model = MODEL

    def analyze(self, result: dict[str, Any]) -> str:
        """
        Analyze a completed BugHunter result.

        The AI receives only structured scan/agent data. It is explicitly
        instructed to distinguish observations from validated findings.
        """

        structured = self._compact(result)

        prompt = (
            "You are the reporting layer for an authorized security assessment.\n\n"
            "Use ONLY the structured JSON supplied below.\n"
            "Do not invent endpoints, vulnerabilities, technologies, CVEs, "
            "attack results, or security controls that are not present in the data.\n"
            "Do not treat an observation or hypothesis as a confirmed vulnerability.\n"
            "Clearly distinguish observations from validated findings.\n"
            "Only describe something as a finding when it appears under "
            "'validated_findings'.\n"
            "If no validated findings exist, explicitly state that no validated "
            "security findings were produced by this assessment.\n"
            "Include severity and confidence when present.\n"
            "Every observation should retain its source URL when one is supplied.\n"
            "Do not claim that a missing security header is automatically a "
            "vulnerability; describe it as an observation unless validated evidence "
            "supports a security impact.\n\n"
            "Use these sections:\n"
            "1. Executive Summary\n"
            "2. Observations\n"
            "3. Validated Findings\n"
            "4. Coverage/Gaps\n"
            "5. Next Safe Steps\n\n"
            "Keep the report concise and technically accurate.\n\n"
            "STRUCTURED BUGHUNTER DATA:\n"
            + json.dumps(structured, indent=2, default=str)
        )

        try:
            response = self.client.models.generate_content(
                model=self.model,
                contents=prompt,
            )

            return response.text or "No AI analysis returned."

        except Exception as e:
            return self._handle_error(e)

    def _compact(self, result: dict[str, Any]) -> dict[str, Any]:
        """
        Convert the full ManagerAgent result into a compact JSON structure
        suitable for Gemini.

        This keeps the AI focused on security-relevant structured data instead
        of sending the entire internal application state.
        """

        execution = result.get("execution", result)

        rows = []

        for item in execution.get("results", []):
            agent_result = item.get("result")

            if hasattr(agent_result, "__dict__"):
                observations = getattr(
                    agent_result,
                    "observations",
                    [],
                )

                hypotheses = getattr(
                    agent_result,
                    "hypotheses",
                    [],
                )

                findings = getattr(
                    agent_result,
                    "findings",
                    [],
                )

                evidence = getattr(
                    agent_result,
                    "evidence",
                    [],
                )

                rows.append(
                    {
                        "agent": item.get("agent"),
                        "status": item.get("status"),
                        "observations": self._serialize_items(observations),
                        "hypotheses": self._serialize_items(hypotheses),
                        "evidence": self._serialize_items(evidence),
                        "findings": self._serialize_items(findings),
                        "hypothesis_count": len(hypotheses),
                        "evidence_count": len(evidence),
                        "finding_count": len(findings),
                        "metadata": getattr(
                            agent_result,
                            "metadata",
                            {},
                        ),
                        "errors": getattr(
                            agent_result,
                            "errors",
                            [],
                        ),
                    }
                )

            else:
                rows.append(item)

        return {
            "target": result.get("target") or execution.get("target"),
            "profile": self._serialize(result.get("profile")),
            "plan": self._serialize(
                result.get("plan") or execution.get("plan", {})
            ),
            "agents": rows,
            "validated_findings": self._serialize_items(
                execution.get("findings", [])
            ),
            "coverage": self._serialize(
                execution.get("coverage", {})
            ),
        }

    def _serialize_items(self, items: Any) -> list[Any]:
        """
        Convert dataclasses/objects into JSON-safe dictionaries.
        """

        if items is None:
            return []

        if not isinstance(items, list):
            items = [items]

        return [
            self._serialize(item)
            for item in items
        ]

    def _serialize(self, value: Any) -> Any:
        """
        Recursively convert common BugHunter objects into JSON-safe values.
        """

        if value is None:
            return None

        if hasattr(value, "__dict__"):
            return {
                key: self._serialize(item)
                for key, item in vars(value).items()
            }

        if isinstance(value, dict):
            return {
                str(key): self._serialize(item)
                for key, item in value.items()
            }

        if isinstance(value, (list, tuple, set)):
            return [
                self._serialize(item)
                for item in value
            ]

        if isinstance(value, (str, int, float, bool)):
            return value

        return str(value)

    def _handle_error(self, error: Exception) -> str:
        """
        Preserve the previous Gemini error handling behavior while keeping
        the analyzer itself clean.
        """

        message_text = str(error)

        print()
        print("========== AI ANALYZER ==========")

        if "429" in message_text or "RESOURCE_EXHAUSTED" in message_text:
            print("Gemini quota exceeded.")
            print("Skipping AI analysis.")

            message = (
                "AI analysis skipped.\n\n"
                "Reason: Gemini quota exceeded."
            )

        elif "401" in message_text:
            print("Invalid Gemini API key.")
            print("Skipping AI analysis.")

            message = (
                "AI analysis skipped.\n\n"
                "Reason: Invalid Gemini API key."
            )

        elif "403" in message_text:
            print("Gemini request forbidden.")
            print("Skipping AI analysis.")

            message = (
                "AI analysis skipped.\n\n"
                "Reason: Access forbidden."
            )

        elif "503" in message_text:
            print("Gemini service unavailable.")
            print("Skipping AI analysis.")

            message = (
                "AI analysis skipped.\n\n"
                "Reason: Gemini service unavailable."
            )

        else:
            print(type(error).__name__)
            print(message_text)

            message = (
                "AI analysis skipped.\n\n"
                f"Reason: {type(error).__name__}"
            )

        print("================================")
        print()

        return message