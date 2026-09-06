from dataclasses import dataclass, field


@dataclass
class RobotsResult:

    found: bool = False

    allow: list[str] = field(
        default_factory=list
    )

    disallow: list[str] = field(
        default_factory=list
    )

    sitemaps: list[str] = field(
        default_factory=list
    )

    interesting_paths: list[str] = field(
        default_factory=list
    )

    user_agents: list[str] = field(
        default_factory=list
    )

    crawl_delay: str = ""

    host: str = ""

    raw: str = ""