from email.mime import text
import re

import requests

from models.javascript_finding import JavaScriptFinding


class JavaScriptAnalyzer:

    URL_REGEX = re.compile(
        r"https?://[^\s\"'<>]+"
    )

    REST_REGEX = re.compile(
        r'["\'](\/(?:api|rest|v\d+)[^"\']*)["\']',
        re.IGNORECASE,
    )

    GRAPHQL_REGEX = re.compile(
        r'["\']([^"\']*graphql[^"\']*)["\']',
        re.IGNORECASE,
    )

    WEBSOCKET_REGEX = re.compile(
        r'["\']((?:ws|wss)://[^"\']+)["\']',
        re.IGNORECASE,
    )

    EMAIL_REGEX = re.compile(
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        re.IGNORECASE,
    )

    TODO_REGEX = re.compile(
        r"(?im)\b(?:TODO|FIXME)\b[:\s-]*(.*)"
    )

    JWT_REGEX = re.compile(
        r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
    )

    def _add_finding(
        self,
        findings,
        seen,
        finding_type,
        value,
        source,
    ):

        key = (finding_type, value)

        if key in seen:
            return

        seen.add(key)

        findings.append(

            JavaScriptFinding(

                type=finding_type,

                value=value,

                source=source,

            )

        )


    def analyze(self, javascript_files):

        findings = []

        seen = set()

        for js in javascript_files:

            try:

                response = requests.get(
                    js.url,
                    timeout=15,
                )

                text = response.text

            except Exception:

                continue

            # -----------------------------------
            # URL Extraction
            # -----------------------------------

            for match in self.URL_REGEX.findall(text):

                self._add_finding(
                    findings,
                    seen,
                    "URL",
                    match,
                    js.url,
                )

            # -----------------------------------
            # REST Endpoint Extraction
            # -----------------------------------

            for endpoint in self.REST_REGEX.findall(text):

                self._add_finding(
                    findings,
                    seen,
                    "REST Endpoint",
                    endpoint,
                    js.url,
                )
                # -----------------------------------
                # GraphQL Endpoint Extraction
                # -----------------------------------

            for endpoint in self.GRAPHQL_REGEX.findall(text):

                self._add_finding(
                    findings,
                    seen,
                    "GraphQL Endpoint",
                    endpoint,
                    js.url,
                )

                # -----------------------------------
                # WebSocket Extraction
                # -----------------------------------
            for websocket in self.WEBSOCKET_REGEX.findall(text):

                self._add_finding(
                     findings,
                     seen,
                     "WebSocket",
                     websocket,
                     js.url,
                 )
 
                 # -----------------------------------
                # Email Extraction
                # -----------------------------------

            for email in self.EMAIL_REGEX.findall(text):

                self._add_finding(
                    findings,
                    seen,
                    "Email",
                    email,
                    js.url,
                )

                # -----------------------------------
                # TODO / FIXME Extraction
                # -----------------------------------

                for todo in self.TODO_REGEX.findall(text):

                    todo = todo.strip()

                    if not todo:
                        continue

                    self._add_finding(
                        findings,
                        seen,
                        "TODO/FIXME",
                        todo,
                        js.url,
                    )

                    # -----------------------------------
                    # JWT Token Extraction
                    # -----------------------------------

                for token in self.JWT_REGEX.findall(text):

                    self._add_finding(
                        findings,
                        seen,
                        "JWT Token",
                        token,
                        js.url,
                    )

        return findings