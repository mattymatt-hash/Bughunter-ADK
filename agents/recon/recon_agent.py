import socket
import requests

from models.scan_result import ScanResult
from tools.httpx_tool import HttpxTool
from tools.subfinder_tool import SubfinderTool


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

        # ----------------------------
        # Subfinder
        # ----------------------------
        try:
            result.subdomains = SubfinderTool().scan(domain)
        except Exception as e:
            print("\n========== SUBFINDER ERROR ==========")
            print(type(e).__name__)
            print(e)
            print("=====================================\n")

        # ----------------------------
        # DNS Lookup
        # ----------------------------
        try:
            result.ip = socket.gethostbyname(domain)
        except Exception:
            pass

        # ----------------------------
        # httpx
        # ----------------------------
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

        # ----------------------------
        # robots.txt
        # ----------------------------
        try:
            result.robots = (
                requests.get(url + "/robots.txt", timeout=10).status_code == 200
            )
        except Exception:
            pass

        # ----------------------------
        # sitemap.xml
        # ----------------------------
        try:
            result.sitemap = (
                requests.get(url + "/sitemap.xml", timeout=10).status_code == 200
            )
        except Exception:
            pass

        return result