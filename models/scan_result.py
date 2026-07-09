from dataclasses import dataclass, field

from models.host_result import HostResult


@dataclass
class ScanResult:

    target: str

    ip: str = ""

    status: int = 0

    server: str = ""

    powered_by: str = ""

    robots: bool = False

    sitemap: bool = False

    title: str = ""

    technologies: list = field(default_factory=list)

    hosts: list[HostResult] = field(default_factory=list)