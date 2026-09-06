from dataclasses import dataclass, field


@dataclass
class JWTResult:

    # -----------------------------------
    # Original Token
    # -----------------------------------

    token: str = ""

    source: str = ""

    # -----------------------------------
    # Decoded Data
    # -----------------------------------

    header: dict = field(default_factory=dict)

    payload: dict = field(default_factory=dict)

    # -----------------------------------
    # Header
    # -----------------------------------

    algorithm: str = ""

    algorithm_none: bool = False

    weak_algorithm: bool = False

    token_type: str = ""

    # -----------------------------------
    # Standard Claims
    # -----------------------------------

    issuer: str = ""

    subject: str = ""

    audience: str = ""

    jwt_id: str = ""

    # -----------------------------------
    # Common Claims
    # -----------------------------------

    scope: str = ""

    roles: list[str] = field(default_factory=list)

    email: str = ""

    # -----------------------------------
    # Time Claims
    # -----------------------------------

    issued_at: str = ""

    expires: str = ""

    expired: bool = False

    has_expiration: bool = False

    lifetime_hours: float = 0.0

    long_lived: bool = False

    # -----------------------------------
    # Errors
    # -----------------------------------

    error: str = ""