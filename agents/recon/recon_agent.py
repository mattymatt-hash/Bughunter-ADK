import socket
import requests

from models.scan_result import ScanResult
from models.host_result import HostResult

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

            hosts = SubfinderTool().scan(domain)

            for host in hosts:

                host_result = HostResult(host=host)

                result.hosts.append(host_result)

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

            # Scan the root domain
            data = httpx.scan(domain)

            if data:
                result.status = data.get("status_code", 0)
                result.server = data.get("webserver", "")
                result.title = data.get("title", "")
                result.technologies = data.get("tech", [])

            # ----------------------------
            # Scan discovered hosts
            # ----------------------------

            total = min(25, len(result.hosts))

            for i, host in enumerate(result.hosts[:25], start=1):

                print(f"Scanning {i}/{total}: {host.host}")

                data = httpx.scan(host.host)

                if not data:
                    continue

                host.status = data.get("status_code", 0)
                host.server = data.get("webserver", "")
                host.title = data.get("title", "")
                host.powered_by = data.get("x_powered_by", "")
                host.technologies = data.get("tech", [])

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