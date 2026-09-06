from dataclasses import dataclass


@dataclass
class HeaderResult:

    # -----------------------------------
    # Target
    # -----------------------------------

    host: str

    error: str = ""

    # -----------------------------------
    # Security Header Presence
    # -----------------------------------

    hsts: bool = False

    csp: bool = False

    x_frame_options: bool = False

    x_content_type_options: bool = False

    referrer_policy: bool = False

    permissions_policy: bool = False

    # -----------------------------------
    # Raw Header Values
    # -----------------------------------

    hsts_value: str = ""

    csp_value: str = ""

    x_frame_options_value: str = ""

    x_content_type_options_value: str = ""

    referrer_policy_value: str = ""

    permissions_policy_value: str = ""

    # -----------------------------------
    # Modern Browser Security Headers
    # -----------------------------------

    cross_origin_embedder_policy: str = ""

    cross_origin_opener_policy: str = ""

    cross_origin_resource_policy: str = ""

    origin_agent_cluster: str = ""

    clear_site_data: str = ""

    # -----------------------------------
    # Misc Headers
    # -----------------------------------

    cors: str = ""

    server: str = ""

    powered_by: str = ""

    content_type: str = ""

    cache_control: str = ""

    etag: str = ""

    date: str = ""

    content_length: str = ""

    # -----------------------------------
    # Scoring
    # -----------------------------------

    security_score: int = 0