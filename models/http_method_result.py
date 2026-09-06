from dataclasses import dataclass, field


@dataclass
class HTTPMethodResult:

    host: str

    methods: list[str] = field(default_factory=list)

    dangerous: list[str] = field(default_factory=list)

    options_supported: bool = False