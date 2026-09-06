@dataclass
class HTTPObservation:

    url: str

    method: str

    status_code: int

    request_headers: dict = field(default_factory=dict)

    response_headers: dict = field(default_factory=dict)

    parameters: list[str] = field(default_factory=list)

    content_type: str = ""

    authenticated: bool = False