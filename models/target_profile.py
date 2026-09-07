from dataclasses import dataclass, field


@dataclass
class TargetProfile:
    target: str

    technologies: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    live_hosts: list[str] = field(default_factory=list)

    endpoints: list[str] = field(default_factory=list)
    api_endpoints: list[str] = field(default_factory=list)
    auth_endpoints: list[str] = field(default_factory=list)
    admin_endpoints: list[str] = field(default_factory=list)
    upload_endpoints: list[str] = field(default_factory=list)
    download_endpoints: list[str] = field(default_factory=list)
    dashboard_endpoints: list[str] = field(default_factory=list)

    graphql_detected: bool = False
    websocket_detected: bool = False
    jwt_detected: bool = False
    llm_detected: bool = False

    authentication_present: bool = False
    authorization_relevant: bool = False
    file_upload_present: bool = False
    payment_related: bool = False
    webhook_present: bool = False

    security_headers: dict = field(default_factory=dict)
    tls_information: list = field(default_factory=list)
    http_methods: list = field(default_factory=list)

    javascript_findings: list = field(default_factory=list)
    jwt_results: list = field(default_factory=list)
