import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import requests

from models.host_result import HostResult
from models.scan_result import ScanResult
from tools.httpx_tool import HttpxTool
from tools.katana_tool import KatanaTool
from tools.subfinder_tool import SubfinderTool


class ReconAgent:

    def __init__(self, max_workers=20):
        self.httpx = HttpxTool()
        self.katana = KatanaTool()
        self.max_workers = max_workers

    def _scan_host(self, host):
        data = self.httpx.scan(host.host)

        if not data:
            return host

        host.status = data.get("status_code", 0)
        host.server = data.get("webserver", "")
        host.title = data.get("title", "")
        host.powered_by = data.get("x_powered_by", "")
        host.technologies = data.get("tech", [])

        return host

    def scan(self, target, host_limit=25):

        start_time = time.time()

        url = target

        if not url.startswith("http"):
            url = "https://" + url

        domain = (
            url.replace("https://", "")
            .replace("http://", "")
            .split("/")[0]
        )

        result = ScanResult(target=domain)

        result.started = datetime.now().isoformat(timespec="seconds")

        if host_limit == 25:
            result.scan_profile = "quick"
        elif host_limit == 250:
            result.scan_profile = "normal"
        elif host_limit is None:
            result.scan_profile = "full"

        # -----------------------------------
        # Subfinder
        # -----------------------------------

        try:
            hosts = SubfinderTool().scan(domain)

            for host in hosts:
                result.hosts.append(
                    HostResult(host=host)
                )

            result.discovered_hosts = len(result.hosts)

        except Exception as e:
            print("\n========== SUBFINDER ERROR ==========")
            print(type(e).__name__)
            print(e)
            print("=====================================\n")

        # -----------------------------------
        # DNS
        # -----------------------------------

        try:
            result.ip = socket.gethostbyname(domain)

        except Exception:
            pass

        # -----------------------------------
        # Root HTTPX Scan
        # -----------------------------------

        try:
            data = self.httpx.scan(domain)

            if data:
                result.status = data.get("status_code", 0)
                result.server = data.get("webserver", "")
                result.title = data.get("title", "")
                result.powered_by = data.get("x_powered_by", "")
                result.technologies = data.get("tech", [])

        except Exception as e:
            print("\n========== ROOT HTTPX ERROR ==========")
            print(type(e).__name__)
            print(e)
            print("======================================\n")

        # -----------------------------------
        # Concurrent Host Scan
        # -----------------------------------

        if host_limit is None:
            total = len(result.hosts)
        else:
            total = min(host_limit, len(result.hosts))

        result.scanned_hosts = total

        print()
        print(f"Scanning {total} hosts using {self.max_workers} workers...")
        print()

        futures = {}

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:

            for host in result.hosts[:total]:
                future = executor.submit(
                    self._scan_host,
                    host
                )

                futures[future] = host.host

            completed = 0

            for future in as_completed(futures):
                completed += 1

                host = future.result()

                print(
                    f"[{completed}/{total}] "
                    f"{host.status:3}  {host.host}"
                )

        # -----------------------------------
        # Katana Crawl
        # -----------------------------------

        try:
            print()
            print("Running Katana...")
            print()

            result.urls = self.katana.scan(
                url,
                depth=1,
                concurrency=10,
                timeout=60,
           )

            result.discovered_urls = len(result.urls)

            print(
                f"Discovered {result.discovered_urls} URLs"
            )

        except Exception as e:
            print("\n========== KATANA ERROR ==========")
            print(type(e).__name__)
            print(e)
            print("==================================\n")

            result.urls = []
            result.discovered_urls = 0

        # -----------------------------------
        # robots.txt
        # -----------------------------------

        try:
            result.robots = (
                requests.get(
                    url + "/robots.txt",
                    timeout=10
                ).status_code == 200
            )

        except Exception:
            pass

        # -----------------------------------
        # sitemap.xml
        # -----------------------------------

        try:
            result.sitemap = (
                requests.get(
                    url + "/sitemap.xml",
                    timeout=10
                ).status_code == 200
            )

        except Exception:
            pass

        # -----------------------------------
        # Statistics
        # -----------------------------------

        live_hosts = [
            h for h in result.hosts
            if h.status > 0
        ]

        result.live_hosts = len(live_hosts)

        result.success_2xx = sum(
            1 for h in live_hosts
            if 200 <= h.status < 300
        )

        result.redirects_3xx = sum(
            1 for h in live_hosts
            if 300 <= h.status < 400
        )

        result.forbidden_403 = sum(
            1 for h in live_hosts
            if h.status == 403
        )

        result.not_found_404 = sum(
            1 for h in live_hosts
            if h.status == 404
        )

        result.server_errors_5xx = sum(
            1 for h in live_hosts
            if 500 <= h.status < 600
        )

        if result.urls:
           result.urls.sort(
           key=lambda x: x.url
      )

        result.finished = datetime.now().isoformat(
            timespec="seconds"
        )

        result.duration = round(
            time.time() - start_time,
            2
        )

        return result