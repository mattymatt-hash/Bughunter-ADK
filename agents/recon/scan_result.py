from dataclasses import dataclass, field


@dataclass
class ScanResult:

    target: str

    ip: str = ""

    status: int = 0

    server: str = ""

    powered_by: str = ""

    robots: bool = False

    sitemap: bool = False

    technologies: list = field(default_factory=list)