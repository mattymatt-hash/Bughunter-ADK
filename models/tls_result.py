from dataclasses import dataclass, field


@dataclass
class TLSResult:

    # --------------------------------------------------
    # Target
    # --------------------------------------------------

    host: str = ""

    valid: bool = False

    error: str = ""

    # --------------------------------------------------
    # TLS
    # --------------------------------------------------

    tls_version: str = ""

    modern_tls: bool = False

    weak_tls: bool = False

    cipher: str = ""

    weak_cipher: bool = False

    # --------------------------------------------------
    # Certificate
    # --------------------------------------------------

    subject: str = ""

    subject_org: str = ""

    issuer: str = ""

    issuer_org: str = ""

    serial_number: str = ""

    version: str = ""

    signature_algorithm: str = ""

    signature_oid: str = ""

    weak_signature: bool = False

    public_key_algorithm: str = ""

    key_size: int = 0

    weak_key: bool = False

    # --------------------------------------------------
    # Certificate Dates
    # --------------------------------------------------

    valid_from: str = ""

    expires: str = ""

    expired: bool = False

    expiration_warning: bool = False

    days_remaining: int = 0

    # --------------------------------------------------
    # Certificate Properties
    # --------------------------------------------------

    wildcard: bool = False

    self_signed: bool = False

    chain_length: int = 0

    certificate_fingerprint: str = ""

    # --------------------------------------------------
    # Subject Alternative Names
    # --------------------------------------------------

    sans: list[str] = field(
        default_factory=list
    )

    # --------------------------------------------------
    # Future Features
    # --------------------------------------------------

    ocsp_enabled: bool = False

    hsts_preload: bool = False

    revoked: bool = False

    trusted: bool = True

    hostname_match: bool = True