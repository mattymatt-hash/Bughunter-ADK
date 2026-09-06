import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from unittest import result
from tools.javascript_tool import JavaScriptTool
from tools.javascript_analyzer import JavaScriptAnalyzer
from tools.jwt_tool import JWTTool
from tools.url_classifier import URLClassifier
import requests
from tools.sitemap_tool import SitemapTool
from models.host_result import HostResult
from models.scan_result import ScanResult
from tools.httpx_tool import HttpxTool
from tools.katana_tool import KatanaTool
from tools.subfinder_tool import SubfinderTool
from tools.robots_tool import RobotsTool
from models.url_result import UrlResult
from tools.header_analyzer import HeaderAnalyzer
from tools.tls_analyzer import TLSAnalyzer
from tools.http_methods_analyzer import HTTPMethodsAnalyzer

class ReconAgent:

    def __init__(self, max_workers=20):
        self.httpx = HttpxTool()
        self.katana = KatanaTool()

        self.javascript = JavaScriptTool()
        self.javascript_analyzer = JavaScriptAnalyzer()
        self.jwt = JWTTool()
        self.url_classifier = URLClassifier()
        self.robots = RobotsTool()
        self.sitemap = SitemapTool()
        self.headers = HeaderAnalyzer()
        self.tls = TLSAnalyzer()
        self.http_methods = HTTPMethodsAnalyzer()

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
            # robots.txt
            # -----------------------------------

            print()
            print("Parsing robots.txt...")

            result.robots = self.robots.scan(url)

                # -----------------------------------
                # sitemap.xml
                # -----------------------------------

            print()
            print("Parsing sitemap.xml...")

            result.sitemap = self.sitemap.scan(url)

            # -----------------------------------
            # Merge Sitemap URLs
            # -----------------------------------

            if result.sitemap.found:

                existing = {
                    u.url
                    for u in result.urls
                }

                added = 0

                for sitemap_url in result.sitemap.urls:

                    if sitemap_url in existing:
                        continue

                    result.urls.append(
                        UrlResult(
                            url=sitemap_url
                        )
                    )

                    existing.add(sitemap_url)
                    added += 1

                if added:

                    print()
                    print(f"Added {added} URLs from sitemap.xml")

                result.discovered_urls = len(result.urls)

            # -----------------------------------
            # URL Classification
            # -----------------------------------

            print()
            print("Classifying URLs...")
            print()

            result.url_categories = (
                self.url_classifier.classify(
                    result.urls
                )
            )
            summary = {}

            for item in result.url_categories:

                summary[item.category] = (
                    summary.get(item.category, 0) + 1
                )

            print("URL Categories")
            print("-" * 35)

            expected = [
                "API",
                "Login",
                "Admin",
                "Dashboard",
                "Auth",
                "Static",
                "Images",
                "Downloads",
                "Documents",
                "Unknown",
            ]

            for category in expected:

                print(
                    f"{category:<15}{summary.get(category,0):>5}"
                )

            print("-" * 35)
            print(
                f"{'Total URLs':<15}{len(result.url_categories):>5}"
            )

                        # -----------------------------------
            # HTTP Security Header Analysis
            # -----------------------------------

            print()
            print("Analyzing Security Headers...")
            print()

            result.header_results = []

            for host in crawl_hosts:

                result.header_results.append(

                    self.headers.analyze(
                        f"https://{host.host}"
                    )

                )

                # -----------------------------------
                # Header Summary
                # -----------------------------------

            print()
            print("Security Headers")
            print("-" * 35)

            total_hosts = len(result.header_results)

            hsts = sum(h.hsts for h in result.header_results)

            csp = sum(h.csp for h in result.header_results)

            xfo = sum(
                h.x_frame_options
                for h in result.header_results
            )

            xcto = sum(
                h.x_content_type_options
                for h in result.header_results
            )

            referrer = sum(
                h.referrer_policy
                for h in result.header_results
            )

            permissions = sum(
            h.permissions_policy
                for h in result.header_results
            )

            print(f"{'HSTS':<22}{hsts:>5}")
            print(f"{'Content Security Policy':<22}{csp:>5}")
            print(f"{'X-Frame-Options':<22}{xfo:>5}")
            print(f"{'X-Content-Type':<22}{xcto:>5}")
            print(f"{'Referrer-Policy':<22}{referrer:>5}")
            print(f"{'Permissions-Policy':<22}{permissions:>5}")

            print("-" * 35)
            print(f"{'Hosts Analyzed':<22}{total_hosts:>5}")
            print()

            critical_headers = [

                ("HSTS", "hsts"),

                ("Content Security Policy", "csp"),

                ("X-Frame-Options", "x_frame_options"),

            ]

            for title, attribute in critical_headers:

                missing = [

                    h.host

                    for h in result.header_results

                    if not getattr(h, attribute)

                ]

                if not missing:
                    continue

                print(f"Missing {title}")
                print("-" * 35)

                for host in missing[:10]:

                    print(host)

                if len(missing) > 10:

                    print(f"... and {len(missing)-10} more")

                print()

            # -----------------------------------
            # TLS Analysis
            # -----------------------------------

            print()
            print("Analyzing TLS...")
            print()

            result.tls_results = []

            for host in crawl_hosts:

                result.tls_results.append(
                    self.tls.analyze(host.host)
                )

            print()
            print("TLS Summary")
            print("-" * 40)

            for tls in result.tls_results:

             print(tls.host)

            print(f"  Version     : {tls.tls_version}")
            print(f"  Cipher      : {tls.cipher}")
            print(f"  Issuer      : {tls.issuer}")
            print(f"  Subject     : {tls.subject}")
            print(f"  Signature   : {tls.signature_algorithm}")

            print(
                f"  Public Key  : "
                f"{tls.public_key_algorithm} "
                f"{tls.key_size}"
            )

            print(f"  Expires     : {tls.days_remaining} days")
            print(f"  Wildcard    : {tls.wildcard}")

            print(
             f"  Fingerprint : "
             f"{tls.certificate_fingerprint}"
            )

            if tls.weak_tls:
                print("  Weak TLS Version")

            if tls.weak_cipher:
                print("  Weak Cipher")

            if tls.weak_signature:
             print("  Weak Signature")

            if tls.expiration_warning:
                print("  Certificate expires within 30 days")

            if tls.self_signed:
                print("  Self Signed")

            if tls.expired:
                print("  Certificate Expired")

            print()

            # -----------------------------------
            # HTTP Methods Analysis
            # -----------------------------------

            print()
            print("Analyzing HTTP Methods...")
            print()

            result.http_methods = []

            for host in crawl_hosts:

                result.http_methods.append(

                self.http_methods.analyze(
                    f"https://{host.host}"
                )

            )

            print()
            print("HTTP Methods")
            print("-" * 40)

            for item in result.http_methods:

                methods = ", ".join(item.methods)

            print(item.host)

            print(f"  Methods : {methods}")

            if item.dangerous:

             print(
                 "  Dangerous : "
                + ", ".join(item.dangerous)
        )

            print()   

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
                "Google API Key",
                "Firebase URL",
                "AWS Keys",
                "Internal IP",
                "Authorization Header"
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

            # -----------------------------------
            # JWT Analysis
            # -----------------------------------

            print()
            print("Running JWT Analysis...")
            print()

            result.jwt_results = []

            for finding in result.javascript_findings:

                if finding.type != "JWT Token":
                    continue

                jwt = self.jwt.decode(
                    finding.value,
                    finding.source,
                )

                result.jwt_results.append(jwt)

            print(
                f"Decoded {len(result.jwt_results)} JWTs"
            )

            except Exception as e:

            result.urls = []
            result.javascript_files = []
            result.javascript_findings = [] 

            print("\n========== KATANA ERROR ==========")
            print(type(e).__name__)
            print(e)
            print("==================================\n")

            result.urls = []
            result.discovered_urls = 0
            result.javascript_files = []
            result.javascript_findings = []

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