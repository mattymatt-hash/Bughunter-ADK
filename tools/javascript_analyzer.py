import re

from config import settings

from models.javascript_finding import JavaScriptFinding
from tools.retry import http


class JavaScriptAnalyzer:

    # --------------------------------------------------
    # Regex Patterns
    # --------------------------------------------------

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

    GITHUB_TOKEN_REGEX = re.compile(
        r"gh[pousr]_[A-Za-z0-9]{36,255}"
    )

    STRIPE_SECRET_REGEX = re.compile(
        r"sk_live_[A-Za-z0-9]+"
    )

    SLACK_TOKEN_REGEX = re.compile(
        r"xox[baprs]-[A-Za-z0-9-]+"
    )

    PRIVATE_KEY_REGEX = re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
    )

    SOURCEMAP_REGEX = re.compile(
        r"sourceMappingURL=([^\r\n]+)"
    )

    # --------------------------------------------------
    # Helper
    # --------------------------------------------------

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

    # --------------------------------------------------
    # Main Analyzer
    # --------------------------------------------------

    def analyze(self, javascript_files):

        findings = []

        seen = set()

        for js in javascript_files:

            try:

                response = http.get(
                    js.url,
                )

                if response is None:
                    continue

                if response.status_code != 200:
                    continue

                # -----------------------------------
                # Fix encoding
                # -----------------------------------

                response.encoding = response.apparent_encoding

                # -----------------------------------
                # Verify JavaScript content
                # -----------------------------------

                content_type = response.headers.get(
                    "Content-Type",
                    "",
                ).lower()

                if (
                    "javascript" not in content_type
                    and "ecmascript" not in content_type
                ):
                    continue

                # -----------------------------------
                # Skip huge JavaScript files
                # -----------------------------------

                if (
                    len(response.content)
                    > settings.MAX_JS_FILE_SIZE
                ):
                    continue

                text = response.text

            except Exception:

                continue

            # -----------------------------------
            # URLs
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
            # REST Endpoints
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
            # GraphQL Endpoints
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
            # WebSockets
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
            # Emails
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
            # TODO / FIXME
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
            # JWT Tokens
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
            # Google API Keys
            # -----------------------------------

            for api_key in self.GOOGLE_API_KEY_REGEX.findall(text):

                self._add_finding(
                    findings,
                    seen,
                    "Google API Key",
                    api_key,
                    js.url,
                )

            # -----------------------------------
            # Firebase URLs
            # -----------------------------------

            for firebase_url in self.FIREBASE_REGEX.findall(text):

                self._add_finding(
                    findings,
                    seen,
                    "Firebase URL",
                    firebase_url,
                    js.url,
                )

            # -----------------------------------
            # AWS Keys
            # -----------------------------------

            for aws_key in self.AWS_KEY_REGEX.findall(text):

                self._add_finding(
                    findings,
                    seen,
                    "AWS Key",
                    aws_key,
                    js.url,
                )

            # -----------------------------------
            # Internal IPs
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
            # Authorization Headers
            # -----------------------------------

            for auth_type, token in self.AUTH_HEADER_REGEX.findall(text):

                self._add_finding(
                    findings,
                    seen,
                    "Authorization Header",
                    f"{auth_type} {token}",
                    js.url,
                )

            # -----------------------------------
            # GitHub Tokens
            # -----------------------------------

            for token in self.GITHUB_TOKEN_REGEX.findall(text):

                self._add_finding(
                    findings,
                    seen,
                    "GitHub Token",
                    token,
                    js.url,
                )

            # -----------------------------------
            # Stripe Secrets
            # -----------------------------------

            for key in self.STRIPE_SECRET_REGEX.findall(text):

                self._add_finding(
                    findings,
                    seen,
                    "Stripe Secret",
                    key,
                    js.url,
                )

            # -----------------------------------
            # Slack Tokens
            # -----------------------------------

            for token in self.SLACK_TOKEN_REGEX.findall(text):

                self._add_finding(
                    findings,
                    seen,
                    "Slack Token",
                    token,
                    js.url,
                )

            # -----------------------------------
            # Private Keys
            # -----------------------------------

            for key in self.PRIVATE_KEY_REGEX.findall(text):

                self._add_finding(
                    findings,
                    seen,
                    "Private Key",
                    key,
                    js.url,
                )

            # -----------------------------------
            # Source Maps
            # -----------------------------------

            for source_map in self.SOURCEMAP_REGEX.findall(text):

                self._add_finding(
                    findings,
                    seen,
                    "Source Map",
                    source_map,
                    js.url,
                )

        return findings