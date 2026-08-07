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

                key = ("URL", match)

                if key in seen:
                    continue

                seen.add(key)

                findings.append(

                    JavaScriptFinding(

                        type="URL",

                        value=match,

                        source=js.url,

                    )

                )

            # -----------------------------------
            # REST Endpoint Extraction
            # -----------------------------------

            for endpoint in self.REST_REGEX.findall(text):

                key = ("REST", endpoint)

                if key in seen:
                    continue

                seen.add(key)

                findings.append(

                    JavaScriptFinding(

                        type="REST Endpoint",

                        value=endpoint,

                        source=js.url,

                    )

                )

        return findings