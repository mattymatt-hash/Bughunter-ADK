from dataclasses import dataclass, field

from models.javascript_finding import JavaScriptFinding
from models.host_result import HostResult
from models.url_result import UrlResult
from models.javascript_file import JavaScriptFile
from models.jwt_result import JWTResult
from models.url_category import URLCategory
from models.sitemap_result import SitemapResult
from models.robots_result import RobotsResult
from models.header_result import HeaderResult
from models.tls_result import TLSResult
from models.http_method_result import HTTPMethodResult


@dataclass
class ScanResult:

    # --------------------------------------------------
    # Target Information
    # --------------------------------------------------

    target: str
    ip: str = ""
    status: int = 0
    title: str = ""
    server: str = ""
    powered_by: str = ""

    # --------------------------------------------------
    # Recon Checks
    # --------------------------------------------------

    robots: RobotsResult = field(
        default_factory=RobotsResult
    )

    sitemap: SitemapResult = field(
        default_factory=SitemapResult
    )

    # --------------------------------------------------
    # Scan Metadata
    # --------------------------------------------------

    scan_profile: str = "quick"
    started: str = ""
    finished: str = ""
    duration: float = 0.0

    # --------------------------------------------------
    # Statistics
    # --------------------------------------------------

    discovered_hosts: int = 0
    scanned_hosts: int = 0
    live_hosts: int = 0

    discovered_urls: int = 0
    archived_urls: int = 0

    duplicate_urls: int = 0

    wayback_urls: int = 0

    commoncrawl_urls: int = 0

    otx_urls: int = 0
    success_2xx: int = 0
    redirects_3xx: int = 0
    forbidden_403: int = 0
    not_found_404: int = 0
    server_errors_5xx: int = 0

    # --------------------------------------------------
    # Technologies
    # --------------------------------------------------

    technologies: list[str] = field(
        default_factory=list
    )

    # --------------------------------------------------
    # Recon Data
    # --------------------------------------------------

    hosts: list[HostResult] = field(
        default_factory=list
    )

    urls: list[UrlResult] = field(
        default_factory=list
    )

    # --------------------------------------------------
    # JavaScript
    # --------------------------------------------------

    javascript_files: list[JavaScriptFile] = field(
        default_factory=list
    )

    javascript_findings: list[JavaScriptFinding] = field(
        default_factory=list
    )

    jwt_results: list[JWTResult] = field(
        default_factory=list
    )

    # --------------------------------------------------
    # URL Classification
    # --------------------------------------------------

    url_categories: list[URLCategory] = field(
        default_factory=list
    )

    # --------------------------------------------------
    # Security
    # --------------------------------------------------

    header_results: list[HeaderResult] = field(
        default_factory=list
    )

    tls_results: list[TLSResult] = field(
        default_factory=list
    )

    http_methods: list[HTTPMethodResult] = field(
        default_factory=list
    )

    # --------------------------------------------------
    # URL Management
    # --------------------------------------------------

    def add_url(self, url_result: UrlResult):

        """
        Adds a URL while automatically merging duplicates.
        """

        for existing in self.urls:

            if existing.url == url_result.url:

                # Merge discovery sources
                if hasattr(existing, "sources"):

                    if url_result.source not in existing.sources:
                        existing.sources.append(
                            url_result.source
                        )

                return

        # First time we've seen this URL
        if hasattr(url_result, "sources"):

            if not url_result.sources:
                url_result.sources.append(
                    url_result.source
                )

        self.urls.append(url_result)

        self.discovered_urls = len(self.urls)

    def add_urls(self, urls: list[UrlResult]):

        """
        Adds multiple URLs using automatic deduplication.
        """

        for url in urls:

            self.add_url(url)