from dataclasses import dataclass, field


@dataclass
class UrlResult:

    url: str

    status: int = 0

    content_type: str = ""

    source: str = ""

    sources: list[str] = field(
        default_factory=list
    )

    length: int = 0