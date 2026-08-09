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

    GOOGLE_API_KEY_REGEX = re.compile(
        r"AIza[0-9A-Za-z\-_]{35}"
    )

    FIREBASE_REGEX = re.compile(
        r"https://[A-Za-z0-9-]+(?:\.firebaseio\.com|\.firebasedatabase\.app)[^\s\"']*",
        re.IGNORECASE,
    )

    AWS_KEY_REGEX = re.compile(
        r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"
    )

    INTERNAL_IP_REGEX = re.compile(
        r"\b(?:"
        r"10(?:\.\d{1,3}){3}|"
        r"192\.168(?:\.\d{1,3}){2}|"
        r"172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}"
        r")\b"
    )

    AUTH_HEADER_REGEX = re.compile(
        r"(?:Authorization|authorization)\s*[:=]\s*[\"']?(Bearer|Basic)\s+([A-Za-z0-9._~+/=-]+)",
        re.IGNORECASE,
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

                    # -----------------------------------
                    # Google API Key Extraction
                    # -----------------------------------

                for key in self.GOOGLE_API_KEY_REGEX.findall(text):

                    self._add_finding(
                        findings,
                        seen,
                        "Google API Key",
                        key,
                        js.url,
                    )

                    # -----------------------------------
                    # Firebase URL Extraction
                    # -----------------------------------

                for url in self.FIREBASE_REGEX.findall(text):

                    self._add_finding(
                        findings,
                        seen,
                        "Firebase URL",
                        url,
                        js.url,
                    )

                    # -----------------------------------
                    # AWS Key Extraction
                    # -----------------------------------

                for key in self.AWS_KEY_REGEX.findall(text):

                    self._add_finding(
                        findings,
                        seen,
                        "AWS Key",
                        key,
                        js.url,
                    )

                    # -----------------------------------
                    # Internal IP Extraction
                    # -----------------------------------

                for ip in self.INTERNAL_IP_REGEX.findall(text):

                    self._add_finding(
                        findings,
                        seen,
                        "Internal IP",
                        ip,
                        js.url,
                    )

                     # -----------------------------------
                     # Authorization Header Extraction
                     # -----------------------------------

                for auth_type, token in self.AUTH_HEADER_REGEX.findall(text):

                    self._add_finding(
                        findings,
                        seen,
                        "Authorization Header",
                        f"{auth_type} {token}",
                        js.url,
                    )              

        return findings
       