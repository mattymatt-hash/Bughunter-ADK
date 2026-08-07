from dataclasses import dataclass


@dataclass
class JavaScriptFile:

    url: str

    status: int = 0

    content_type: str = ""

    size: int = 0

    sha256: str = ""