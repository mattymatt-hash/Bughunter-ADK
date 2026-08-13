from dataclasses import dataclass


@dataclass
class JWTResult:

    algorithm: str = ""

    token_type: str = ""

    issuer: str = ""

    subject: str = ""

    audience: str = ""

    issued_at: str = ""

    expires: str = ""

    expired: bool = False

    token: str = ""

    source: str = ""