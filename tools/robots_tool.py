from urllib.parse import urljoin

from models.robots_result import RobotsResult
from tools.retry import http


class RobotsTool:

    INTERESTING_WORDS = (
        "admin",
        "administrator",
        "login",
        "signin",
        "auth",
        "oauth",
        "api",
        "graphql",
        "swagger",
        "openapi",
        "backup",
        "backups",
        "private",
        "internal",
        "config",
        "secret",
        "test",
        "testing",
        "stage",
        "staging",
        "dev",
        "development",
        "debug",
        "dashboard",
        "console",
        "upload",
        "download",
        "db",
        "database",
        "git",
        ".env",
        "jenkins",
    )

    def scan(self, base_url):

        result = RobotsResult()

        try:

            response = http.get(
                base_url.rstrip("/") + "/robots.txt",
            )

            if response is None:
                return result

        except Exception:

            return result

        if response.status_code != 200:
            return result

        response.encoding = response.apparent_encoding

        result.found = True
        result.raw = response.text

        for line in response.text.splitlines():

            line = line.strip()

            if not line:
                continue

            if line.startswith("#"):
                continue

            lower = line.lower()

            # -----------------------------------
            # User-Agent
            # -----------------------------------

            if lower.startswith("user-agent:"):

                agent = line.split(":", 1)[1].strip()

                if agent:

                    result.user_agents.append(agent)

            # -----------------------------------
            # Disallow
            # -----------------------------------

            elif lower.startswith("disallow:"):

                path = line.split(":", 1)[1].strip()

                if not path:
                    continue

                result.disallow.append(path)

                if any(
                    word in path.lower()
                    for word in self.INTERESTING_WORDS
                ):

                    result.interesting_paths.append(path)

            # -----------------------------------
            # Allow
            # -----------------------------------

            elif lower.startswith("allow:"):

                path = line.split(":", 1)[1].strip()

                if not path:
                    continue

                result.allow.append(path)

            # -----------------------------------
            # Sitemap
            # -----------------------------------

            elif lower.startswith("sitemap:"):

                sitemap = line.split(":", 1)[1].strip()

                if not sitemap:
                    continue

                sitemap = urljoin(
                    base_url,
                    sitemap,
                )

                result.sitemaps.append(sitemap)

            # -----------------------------------
            # Crawl Delay
            # -----------------------------------

            elif lower.startswith("crawl-delay:"):

                result.crawl_delay = (
                    line.split(":", 1)[1].strip()
                )

            # -----------------------------------
            # Host
            # -----------------------------------

            elif lower.startswith("host:"):

                result.host = (
                    line.split(":", 1)[1].strip()
                )

        # -----------------------------------
        # Remove Duplicates
        # -----------------------------------

        result.disallow = sorted(
            set(result.disallow)
        )

        result.allow = sorted(
            set(result.allow)
        )

        result.sitemaps = sorted(
            set(result.sitemaps)
        )

        result.interesting_paths = sorted(
            set(result.interesting_paths)
        )

        result.user_agents = sorted(
            set(result.user_agents)
        )

        return result