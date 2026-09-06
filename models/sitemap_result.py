from dataclasses import dataclass, field


@dataclass
class SitemapResult:

    found: bool = False

    urls: list[str] = field(default_factory=list)

    images: list[str] = field(default_factory=list)

    news: list[str] = field(default_factory=list)

    alternate_languages: list[str] = field(default_factory=list)

    apis: list[str] = field(default_factory=list)

    sitemaps: list[str] = field(default_factory=list)