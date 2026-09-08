from __future__ import annotations

from uuid import uuid4
from html.parser import HTMLParser
from typing import Any
from urllib.parse import parse_qs, urlparse, urljoin

import requests

from agents.base_agent import BaseSecurityAgent
from models.agent_result import AgentResult
from models.hypothesis import Hypothesis


class _FormParser(HTMLParser):
    """Passively extracts HTML form input metadata."""

    def __init__(self) -> None:
        super().__init__()

        self.forms: list[dict[str, Any]] = []
        self._form: dict[str, Any] | None = None

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:

        attrs_dict = dict(attrs)
        tag_lower = tag.lower()

        if tag_lower == "form":
            self._form = {
                "action": attrs_dict.get("action") or "",
                "method": (
                    attrs_dict.get("method") or "GET"
                ).upper(),
                "inputs": [],
            }

        elif (
            self._form is not None
            and tag_lower in {"input", "textarea", "select"}
        ):
            name = attrs_dict.get("name")

            if name:
                self._form["inputs"].append({
                    "name": name,
                    "type": attrs_dict.get("type") or tag_lower,
                })

    def handle_endtag(self, tag: str) -> None:
        if (
            tag.lower() == "form"
            and self._form is not None
        ):
            self.forms.append(self._form)
            self._form = None


class XssAgent(BaseSecurityAgent):
    name = "xss"

    description = (
        "Passively analyzes application input and JavaScript "
        "surfaces for XSS hypotheses."
    )

    def run(
        self,
        scan_result: Any,
        target_profile: Any,
        context: dict[str, Any] | None = None,
    ) -> AgentResult:

        target = (
            getattr(target_profile, "target", None)
            or getattr(scan_result, "target", "unknown")
        )

        result = AgentResult(
            agent=self.name,
            target=target,
            metadata={
                "phase": 1,
                "implemented": True,
                "analysis_type": "recon_driven",
                "destructive_testing": False,
                "urls_reviewed": 0,
                "forms_discovered": 0,
                "query_parameters": 0,
                "javascript_finding_count": 0,
            },
        )

        # Target profile endpoint inventory.
        endpoints = list(
            getattr(target_profile, "endpoints", []) or []
        )

        # JavaScript findings discovered during reconnaissance.
        javascript_findings = list(
            getattr(
                target_profile,
                "javascript_findings",
                [],
            )
            or []
        )

        result.metadata["javascript_finding_count"] = (
            len(javascript_findings)
        )

        # ScanResult URL inventory.
        scan_urls = list(
            getattr(scan_result, "urls", []) or []
        )

        # Combine profile endpoints and scan URLs.
        urls: list[str] = []
        seen_urls: set[str] = set()

        for endpoint in endpoints:
            endpoint_url = self._extract_url(endpoint)

            if endpoint_url and endpoint_url not in seen_urls:
                seen_urls.add(endpoint_url)
                urls.append(endpoint_url)

        for item in scan_urls:
            item_url = self._extract_url(item)

            if item_url and item_url not in seen_urls:
                seen_urls.add(item_url)
                urls.append(item_url)

        # General XSS attack-surface observation.
        result.add_observation({
            "type": "xss_surface",
            "source_url": target,
            "endpoint_count": len(endpoints),
            "url_count": len(urls),
            "javascript_finding_count": len(
                javascript_findings
            ),
            "message": (
                "Application input and JavaScript surfaces "
                "were reviewed using passive reconnaissance."
            ),
            "severity": "info",
            "confidence": 0.95,
        })

        # ------------------------------------------------------------------
        # Query parameter analysis
        # ------------------------------------------------------------------

        for url in urls:

            if not url.startswith(
                ("http://", "https://")
            ):
                continue

            result.metadata["urls_reviewed"] += 1

            parsed = urlparse(url)

            parameters = list(
                parse_qs(
                    parsed.query,
                    keep_blank_values=True,
                ).keys()
            )

            if not parameters:
                continue

            result.metadata["query_parameters"] += len(
                parameters
            )

            result.add_observation({
                "type": "query_parameter_input",
                "source_url": url,
                "message": (
                    "Query-string parameters are present and "
                    "represent an XSS input surface; no payload "
                    "was submitted."
                ),
                "parameters": parameters,
                "severity": "low",
                "confidence": 0.95,
            })

            hypothesis = Hypothesis(
                id=f"{self.name}-{uuid4().hex[:12]}",
                agent=self.name,
                vulnerability_type="reflected_input_surface",
                target=url,
                description=(
                    "Review reflection and output encoding for "
                    f"parameters {', '.join(parameters)} on {url}."
                ),
                confidence=0.45,
                priority="medium",
                status="pending",
                metadata={
                    "phase": 1,
                    "source_url": url,
                    "parameters": parameters,
                    "destructive_testing": False,
                },
            )

            result.add_hypothesis(hypothesis)

        # ------------------------------------------------------------------
        # Passive HTML form discovery
        # ------------------------------------------------------------------

        for url in urls:

            if not url.startswith(
                ("http://", "https://")
            ):
                continue

            try:
                response = requests.get(
                    url,
                    timeout=5,
                    allow_redirects=True,
                    headers={
                        "User-Agent": "BugHunter-ADK/0.6"
                    },
                )

                content_type = response.headers.get(
                    "content-type",
                    "",
                ).lower()

                # Only parse HTML responses.
                if "html" not in content_type:
                    continue

                parser = _FormParser()

                # Prevent excessively large responses from being parsed.
                parser.feed(
                    response.text[:1_000_000]
                )

                for form in parser.forms:

                    action = (
                        form["action"]
                        or response.url
                    )

                    # Resolve relative form actions into URLs.
                    resolved_action = urljoin(
                        response.url,
                        action,
                    )

                    result.metadata[
                        "forms_discovered"
                    ] += 1

                    input_names = [
                        item["name"]
                        for item in form["inputs"]
                    ]

                    result.add_observation({
                        "type": "html_form_input",
                        "source_url": response.url,
                        "message": (
                            "HTML form contains user-controlled "
                            "input fields; no form submission "
                            "was performed."
                        ),
                        "action": resolved_action,
                        "method": form["method"],
                        "inputs": form["inputs"],
                        "severity": "low",
                        "confidence": 0.90,
                    })

                    hypothesis = Hypothesis(
                        id=f"{self.name}-{uuid4().hex[:12]}",
                        agent=self.name,
                        vulnerability_type="stored_input_surface",
                        target=response.url,
                        description=(
                            "Review output handling for form inputs "
                            f"on {response.url}."
                        ),
                        confidence=0.40,
                        priority="medium",
                        status="pending",
                        metadata={
                            "phase": 1,
                            "source_url": response.url,
                            "action": resolved_action,
                            "method": form["method"],
                            "inputs": input_names,
                            "destructive_testing": False,
                        },
                    )

                    result.add_hypothesis(
                        hypothesis
                    )

            except requests.RequestException as exc:

                result.add_observation({
                    "type": "form_discovery_error",
                    "source_url": url,
                    "message": (
                        "Passive HTML form discovery failed: "
                        f"{type(exc).__name__}"
                    ),
                    "severity": "info",
                    "confidence": 0.50,
                })

        # ------------------------------------------------------------------
        # JavaScript analysis
        # ------------------------------------------------------------------

        if javascript_findings:

            result.add_observation({
                "type": "javascript_input_surface",
                "source_url": target,
                "message": (
                    "JavaScript findings were discovered during "
                    "reconnaissance and should be reviewed for "
                    "client-side input and output handling."
                ),
                "finding_count": len(
                    javascript_findings
                ),
                "severity": "low",
                "confidence": 0.85,
            })

            hypothesis = Hypothesis(
                id=f"{self.name}-{uuid4().hex[:12]}",
                agent=self.name,
                vulnerability_type="javascript_sink_surface",
                target=target,
                description=(
                    "Review discovered JavaScript findings for "
                    "client-side input flows and potentially "
                    "dangerous output sinks."
                ),
                confidence=0.60,
                priority="medium",
                status="pending",
                metadata={
                    "phase": 1,
                    "javascript_finding_count": len(
                        javascript_findings
                    ),
                    "destructive_testing": False,
                },
            )

            result.add_hypothesis(
                hypothesis
            )

        # ------------------------------------------------------------------
        # Broader XSS hypotheses
        # ------------------------------------------------------------------

        if urls or endpoints:

            broader_hypotheses = [
                (
                    "reflected_input_surface",
                    "Review endpoint input parameters for reflected "
                    "input and output paths.",
                    "high",
                ),
                (
                    "stored_input_surface",
                    "Review application inputs that may be persisted "
                    "and later rendered.",
                    "high",
                ),
                (
                    "dom_input_surface",
                    "Review client-side input flows for DOM-based "
                    "output handling.",
                    "high",
                ),
            ]

            # Avoid creating duplicate broad hypotheses when specific
            # query/form/JavaScript hypotheses already exist.
            existing_types = {
                hypothesis.vulnerability_type
                for hypothesis in result.hypotheses
            }

            for (
                vulnerability_type,
                description,
                priority,
            ) in broader_hypotheses:

                if (
                    vulnerability_type
                    in existing_types
                ):
                    continue

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
                        "endpoint_count": len(
                            endpoints
                        ),
                        "url_count": len(urls),
                        "destructive_testing": False,
                    },
                )

                result.add_hypothesis(
                    hypothesis
                )

        # ------------------------------------------------------------------
        # Empty surface summary
        # ------------------------------------------------------------------

        if (
            result.metadata["query_parameters"] == 0
            and result.metadata["forms_discovered"] == 0
            and not javascript_findings
        ):

            result.add_observation({
                "type": "xss_surface_summary",
                "source_url": target,
                "message": (
                    "No query parameters, HTML forms, or "
                    "JavaScript findings were discovered during "
                    "passive XSS analysis."
                ),
                "severity": "info",
                "confidence": 0.90,
            })

        # Final metadata.
        result.metadata.update({
            "hypothesis_count": len(
                result.hypotheses
            ),
            "observation_count": len(
                result.observations
            ),
        })

        return result

    @staticmethod
    def _extract_url(item: Any) -> str:
        """
        Extract a URL from either a string, dataclass-like object,
        or dictionary.
        """

        if isinstance(item, str):
            return item

        if isinstance(item, dict):
            return str(
                item.get("url", "")
                or item.get("endpoint", "")
            )

        return str(
            getattr(item, "url", "")
            or getattr(item, "endpoint", "")
        )

