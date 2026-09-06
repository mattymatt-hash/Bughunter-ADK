

from models.url_result import UrlResult
from tools.retry import http


class WaybackTool:

    API = (
        "https://web.archive.org/cdx/search/cdx"
    )


    def scan(
        self,
        domain,
    ):

        results = []

        try:

            response = http.get(

                self.API,

                params={

                    "url": f"{domain}/*",

                    "output": "json",

                    "fl": "original",

                    "collapse": "urlkey",

                },

            )

            if response is None:

                return results

            response.raise_for_status()

            data = response.json()

        except Exception:

            return results

        seen = set()

        #
        # Skip header row
        #

        for row in data[1:]:

            if not row:
                continue

            url = row[0]

            if not url:
                continue

            if url in seen:
                continue

            seen.add(url)

            results.append(

                UrlResult(

                    url=url,

                    source="wayback",

                    status=200,

                )

            )

        return results