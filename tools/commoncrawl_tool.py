import json

from config import settings

from models.url_result import UrlResult
from tools.retry import http
from tools.url_filter import URLFilter


class CommonCrawlTool:

    INDEX_API = (
        "https://index.commoncrawl.org/collinfo.json"
    )

    def __init__(self):

        self.http = http

        self.filter = URLFilter()

    # --------------------------------------------------
    # Latest Common Crawl Index
    # --------------------------------------------------

    def latest_index(self):

        try:

            response = self.http.get(

                self.INDEX_API,

                timeout=settings.REQUEST_TIMEOUT,

                headers={

                    "User-Agent": settings.USER_AGENT,

                },

                verify=settings.VERIFY_SSL,

            )

            if response is None:

                return None

            response.raise_for_status()

            indexes = response.json()

        except Exception:

            return None

        if not indexes:

            return None

        return indexes[0]["id"]

    # --------------------------------------------------
    # Scan
    # --------------------------------------------------

    def scan(
        self,
        domain,
    ):

        results = []

        index = self.latest_index()

        if not index:

            return results

        try:

            response = self.http.get(

                f"https://index.commoncrawl.org/{index}-index",

                params={

                    "url": f"{domain}/*",

                    "output": "json",

                },

                timeout=settings.REQUEST_TIMEOUT,

                headers={

                    "User-Agent": settings.USER_AGENT,

                },

                verify=settings.VERIFY_SSL,

                stream=True,

            )

            if response is None:

                return results

            response.raise_for_status()

        except Exception:

            return results

        seen = set()

        for line in response.iter_lines():

            if not line:
                continue

            try:

                item = json.loads(line)

            except Exception:

                continue

            url = item.get("url")

            if not url:
                continue

            if url in seen:
                continue

            seen.add(url)

            if not self.filter.interesting(url):
                continue

            results.append(

                UrlResult(

                    url=url,

                    source="commoncrawl",

                    status=200,

                )

            )

        return results