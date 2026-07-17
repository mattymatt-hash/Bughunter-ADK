from dataclasses import dataclass


@dataclass
class UrlResult:

    url: str

    status: int = 0

    content_type: str = ""

    source: str = "katana"

    length: int = 0