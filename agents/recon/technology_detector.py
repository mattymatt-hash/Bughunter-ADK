import requests


class TechnologyDetector:

    def detect(self, url):

        technologies = []

        try:
            response = requests.get(url, timeout=10)

            headers = response.headers
            html = response.text.lower()

            server = headers.get("Server", "").lower()
            powered = headers.get("X-Powered-By", "").lower()

            if "cloudflare" in server:
                technologies.append("Cloudflare")

            if "nginx" in server:
                technologies.append("Nginx")

            if "apache" in server:
                technologies.append("Apache")

            if "iis" in server:
                technologies.append("Microsoft IIS")

            if "php" in powered:
                technologies.append("PHP")

            if "asp.net" in powered:
                technologies.append("ASP.NET")

            if "_next" in html:
                technologies.append("Next.js")

            if "__next" in html:
                technologies.append("React")

            if "wp-content" in html:
                technologies.append("WordPress")

            if "tailwind" in html:
                technologies.append("Tailwind CSS")

            if "graphql" in html:
                technologies.append("GraphQL")

            return sorted(list(set(technologies)))

        except Exception:

            return []