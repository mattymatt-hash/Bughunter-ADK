import socket
import requests

from models.scan_result import ScanResult
from tools.httpx_tool import HttpxTool


class ReconAgent:

    def scan(self, target):

        url = target

        if not url.startswith("http"):
            url = "https://" + url

        domain = (
            url.replace("https://", "")
            .replace("http://", "")
            .split("/")[0]
        )

        result = ScanResult(target=domain)

        try:
            result.ip = socket.gethostbyname(domain)
        except Exception:
            pass

        httpx = HttpxTool()

        try:
            data = httpx.scan(domain)

            if data:

                result.status = data.get("status_code", 0)

                result.server = data.get("webserver", "")

                result.title = data.get("title", "")

                result.technologies = data.get("tech", [])

        except Exception as e:

            print("\n========== HTTPX ERROR ==========")
            print(type(e).__name__)
            print(e)
            print("=================================\n")
       
        try:
            result.robots = (
                requests.get(url + "/robots.txt").status_code == 200
            )
        except Exception:
            pass

        try:
            result.sitemap = (
                requests.get(url + "/sitemap.xml").status_code == 200
            )
        except Exception:
            pass

        return result