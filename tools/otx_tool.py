from config import settings

from models.url_result import UrlResult
from tools.retry import http


class OTXTool:

    API = (
        "https://otx.alienvault.com/api/v1/indicators/domain/{}/url_list"
    )

    def scan(
        self,
        domain,
    ):

        results = []

        try:

            headers = {}

            if settings.OTX_API_KEY:

                headers["X-OTX-API-KEY"] = (
                    settings.OTX_API_KEY
                )

            response = http.get(

                self.API.format(domain),

                headers=headers,

            )

            if response is None:

                return results

            response.raise_for_status()

            data = response.json()

        except Exception:

            return results

        seen = set()

        for item in data.get(
            "url_list",
            [],
        ):

            url = item.get("url")

            if not url:
                continue

            if url in seen:
                continue

            seen.add(url)

            results.append(

                UrlResult(

                    url=url,

                    source="otx",

                    status=item.get(
                        "httpcode",
                        0,
                    ),

                )

            )

        return results