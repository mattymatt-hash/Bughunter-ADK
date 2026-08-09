import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from unittest import result
from tools.javascript_tool import JavaScriptTool
from tools.javascript_analyzer import JavaScriptAnalyzer

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
        self.javascript = JavaScriptTool()
        self.javascript_analyzer = JavaScriptAnalyzer()
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

        domain = url.replace("https://", "").replace("http://", "").split("/")[0]

        result = ScanResult(target=domain)

        result.started = datetime.now().isoformat(timespec="seconds")

        if host_limit == 25:
            result.scan_profile = "quick"
        elif host_limit == 250:
            result.scan_profile = "normal"
        elif host_limit is None:
            result.scan_profile = "full"

        # -----------------------------------
        # Katana Scan Settings
        # -----------------------------------

        if result.scan_profile == "quick":

            katana_depth = 1
            katana_concurrency = 5
            katana_timeout = 15

        elif result.scan_profile == "normal":

            katana_depth = 2
            katana_concurrency = 10
            katana_timeout = 30

        else:

            katana_depth = 3
            katana_concurrency = 20
            katana_timeout = 90

        # -----------------------------------
        # Subfinder
        # -----------------------------------

        try:
            hosts = SubfinderTool().scan(domain)

            for host in hosts:
                result.hosts.append(HostResult(host=host))

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
                future = executor.submit(self._scan_host, host)

                futures[future] = host.host

            completed = 0

            for future in as_completed(futures):
                completed += 1

                host = future.result()

                print(f"[{completed}/{total}] " f"{host.status:3}  {host.host}")
            # -----------------------------------
            # Select Live Hosts
            # -----------------------------------

            crawl_hosts = []

            for host in result.hosts:

                if host.status in (
                    200,
                    201,
                    202,
                    203,
                    204,
                    205,
                    206,
                    207,
                    208,
                    226,
                ):

                    crawl_hosts.append(host)
        # -----------------------------------
        # Katana Crawl
        # -----------------------------------

        try:
            print()
            print("Running Katana...")
            print(
                f"Profile: {result.scan_profile} | "
                f"Depth: {katana_depth} | "
                f"Workers: {katana_concurrency} | "
                f"Timeout: {katana_timeout}s"
            )
            print()

            result.urls = []

            for index, host in enumerate(crawl_hosts, start=1):

                print(f"Crawling {index}/{len(crawl_hosts)}: " f"https://{host.host}")

                urls = self.katana.scan(
                    f"https://{host.host}",
                    depth=katana_depth,
                    concurrency=katana_concurrency,
                    timeout=katana_timeout,
                )

                result.urls.extend(urls)

            result.discovered_urls = len(result.urls)

            # -----------------------------------
              # JavaScript Discovery
            # -----------------------------------

            print()
            print("Running JavaScript Discovery...")
            print(f"Scanning {len(result.urls)} discovered URLs...")
            print()

            result.javascript_files = self.javascript.scan(result.urls)

            print()

            if result.javascript_files:
                print(
                    f"Discovered {len(result.javascript_files)} JavaScript files"
             )
            else:
                print("No JavaScript files discovered.")

      # Show the first 10 discovered URLs
            for url in result.urls[:10]:
                print(f"  {url.url}")

      # If there are more than 10, show a summary
            if len(result.urls) > 10:
                print(f"\n... and {len(result.urls) - 10} more URLs")


            # -----------------------------------
            # JavaScript Analysis
            # -----------------------------------

            print()
            print("Running JavaScript Analysis...")
            print()

            result.javascript_findings = (
                self.javascript_analyzer.analyze(
                    result.javascript_files
                )
            )

            print()

            print("JavaScript Findings")
            print("-" * 35)

            expected = [
                "URL",
                "REST Endpoint",
                "GraphQL Endpoint",
                "WebSocket",
                "Email",
                "TODO/FIXME",
                "JWT Token",
            ]

            summary = {}

            for finding in result.javascript_findings:
                summary[finding.type] = (
                summary.get(finding.type, 0) + 1
                )

            for finding_type in expected:
                print(
                    f"{finding_type:<20} {summary.get(finding_type, 0):>5}"
                )

            print("-" * 35)
            print(
                f"{'Total Findings':<20} {len(result.javascript_findings):>5}"
            )

        except Exception as e:

            print("\n========== KATANA ERROR ==========")
            print(type(e).__name__)
            print(e)
            print("==================================\n")

            result.urls = []
            result.discovered_urls = 0
            result.javascript_files = []
            result.javascript_findings = []

        # -----------------------------------
        # robots.txt
        # -----------------------------------

        try:
            result.robots = (
                requests.get(url + "/robots.txt", timeout=10).status_code == 200
            )

        except Exception:
            pass

        # -----------------------------------
        # sitemap.xml
        # -----------------------------------

        try:
            result.sitemap = (
                requests.get(url + "/sitemap.xml", timeout=10).status_code == 200
            )

        except Exception:
            pass

        # -----------------------------------
        # Statistics
        # -----------------------------------

        live_hosts = [h for h in result.hosts if h.status > 0]

        result.live_hosts = len(live_hosts)

        result.success_2xx = sum(1 for h in live_hosts if 200 <= h.status < 300)

        result.redirects_3xx = sum(1 for h in live_hosts if 300 <= h.status < 400)

        result.forbidden_403 = sum(1 for h in live_hosts if h.status == 403)

        result.not_found_404 = sum(1 for h in live_hosts if h.status == 404)

        result.server_errors_5xx = sum(1 for h in live_hosts if 500 <= h.status < 600)

        if result.urls:
            result.urls.sort(key=lambda x: x.url)

        result.finished = datetime.now().isoformat(timespec="seconds")

        result.duration = round(time.time() - start_time, 2)

        return result
