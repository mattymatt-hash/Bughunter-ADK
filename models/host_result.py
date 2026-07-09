from dataclasses import dataclass, field


@dataclass
class HostResult:

    host: str

    status: int = 0

    title: str = ""

    server: str = ""

    powered_by: str = ""

    technologies: list = field(default_factory=list)