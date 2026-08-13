from dataclasses import dataclass, field
from models.javascript_finding import JavaScriptFinding
from models.host_result import HostResult
from models.url_result import UrlResult
from models.javascript_file import JavaScriptFile
from models.jwt_result import JWTResult
from models.url_category import URLCategory

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

    robots: bool = False
    sitemap: bool = False

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

    success_2xx: int = 0
    redirects_3xx: int = 0
    forbidden_403: int = 0
    not_found_404: int = 0
    server_errors_5xx: int = 0

    # --------------------------------------------------
    # Technologies
    # --------------------------------------------------

    technologies: list[str] = field(default_factory=list)

    # --------------------------------------------------
    # Recon Data
    # --------------------------------------------------

    hosts: list[HostResult] = field(default_factory=list)

    urls: list[UrlResult] = field(default_factory=list)

    jwt_results: list[JWTResult] = field(default_factory=list)

    # -----------------------------------
    # JavaScript
    # -----------------------------------

    javascript_files: list[JavaScriptFile] = field(default_factory=list)

    javascript_findings: list[JavaScriptFinding] = field(default_factory=list)

    jwt_results: list[JWTResult] = field(default_factory=list)

    url_categories: list[URLCategory] = field(default_factory=list)