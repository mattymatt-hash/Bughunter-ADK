import hashlib

import requests

from models.javascript_file import JavaScriptFile


class JavaScriptTool:

    def scan(self, urls):

        results = []

        seen = set()

        for item in urls:

            url = item.url

            # Only JavaScript files
            if not url.lower().endswith(".js"):
                continue

            if url in seen:
                continue

            seen.add(url)

            try:

                response = requests.get(
                    url,
                    timeout=15,
                )

                sha256 = hashlib.sha256(
                    response.content
                ).hexdigest()

                results.append(

                    JavaScriptFile(

                        url=url,

                        status=response.status_code,

                        content_type=response.headers.get(
                            "Content-Type",
                            "",
                        ),

                        size=len(response.content),

                        sha256=sha256,

                    )

                )

            except Exception:

                pass

        return results