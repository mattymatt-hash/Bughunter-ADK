import hashlib
import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import (
    rsa,
    ec,
    ed25519,
    ed448,
)
from cryptography.x509.oid import NameOID

from config import settings
from models.tls_result import TLSResult


class TLSAnalyzer:

    def analyze(self, host):

        result = TLSResult(host=host)

        try:

            # -----------------------------------
            # SSL Context
            # -----------------------------------

            context = ssl.create_default_context()

            context.check_hostname = settings.VERIFY_SSL

            context.verify_mode = (
                ssl.CERT_REQUIRED
                if settings.VERIFY_SSL
                else ssl.CERT_NONE
            )

            with socket.create_connection(
                (host, 443),
                timeout=settings.TLS_TIMEOUT,
            ) as sock:

                with context.wrap_socket(
                    sock,
                    server_hostname=host,
                ) as tls:

                    result.valid = True

                    # -----------------------------------
                    # TLS Version
                    # -----------------------------------

                    result.tls_version = tls.version()

                    result.modern_tls = (
                        result.tls_version == "TLSv1.3"
                    )

                    result.weak_tls = (
                        result.tls_version
                        in (
                            "TLSv1",
                            "TLSv1.1",
                        )
                    )

                    # -----------------------------------
                    # Cipher
                    # -----------------------------------

                    cipher = tls.cipher()

                    if cipher:

                        result.cipher = cipher[0]

                        weak = (
                            "RC4",
                            "DES",
                            "3DES",
                            "NULL",
                            "MD5",
                            "EXPORT",
                        )

                        result.weak_cipher = any(
                            item in result.cipher.upper()
                            for item in weak
                        )

                    # -----------------------------------
                    # Certificate
                    # -----------------------------------

                    cert = tls.getpeercert()

                    der = tls.getpeercert(
                        binary_form=True
                    )

                    # -----------------------------------
                    # SHA256 Fingerprint
                    # -----------------------------------

                    fingerprint = hashlib.sha256(
                        der
                    ).hexdigest().upper()

                    result.certificate_fingerprint = ":".join(

                        fingerprint[i:i + 2]

                        for i in range(
                            0,
                            len(fingerprint),
                            2,
                        )

                    )

                    # -----------------------------------
                    # Parse X509
                    # -----------------------------------

                    x509_cert = (
                        x509.load_der_x509_certificate(
                            der
                        )
                    )

                    result.chain_length = 1

                    result.serial_number = format(
                        x509_cert.serial_number,
                        "X",
                    )

                    result.version = (
                        x509_cert.version.name
                    )

                    result.signature_oid = str(
                        x509_cert.signature_algorithm_oid
                    )

                    # -----------------------------------
                    # Signature Algorithm
                    # -----------------------------------

                    try:

                        result.signature_algorithm = (
                            x509_cert.signature_hash_algorithm.name.upper()
                        )

                        result.weak_signature = (
                            result.signature_algorithm
                            in (
                                "SHA1",
                                "MD5",
                            )
                        )

                    except Exception:

                        result.signature_algorithm = ""

                    # -----------------------------------
                    # Public Key
                    # -----------------------------------

                    public_key = x509_cert.public_key()

                    if isinstance(
                        public_key,
                        rsa.RSAPublicKey,
                    ):

                        result.public_key_algorithm = "RSA"

                    elif isinstance(
                        public_key,
                        ec.EllipticCurvePublicKey,
                    ):

                        result.public_key_algorithm = "ECDSA"

                    elif isinstance(
                        public_key,
                        ed25519.Ed25519PublicKey,
                    ):

                        result.public_key_algorithm = "Ed25519"

                    elif isinstance(
                        public_key,
                        ed448.Ed448PublicKey,
                    ):

                        result.public_key_algorithm = "Ed448"

                    else:

                        result.public_key_algorithm = (
                            type(public_key).__name__
                        )

                    if hasattr(
                        public_key,
                        "key_size",
                    ):

                        result.key_size = (
                            public_key.key_size
                        )

                        if (
                            result.public_key_algorithm
                            == "RSA"
                        ):

                            result.weak_key = (
                                result.key_size < 2048
                            )

                    # -----------------------------------
                    # Organizations
                    # -----------------------------------

                    try:

                        result.subject_org = (

                            x509_cert.subject
                            .get_attributes_for_oid(
                                NameOID.ORGANIZATION_NAME
                            )[0]
                            .value

                        )

                    except Exception:

                        pass

                    try:

                        result.issuer_org = (

                            x509_cert.issuer
                            .get_attributes_for_oid(
                                NameOID.ORGANIZATION_NAME
                            )[0]
                            .value

                        )

                    except Exception:

                        pass

        except Exception as e:

            result.valid = False

            result.error = str(e)

            return result

        self._parse_certificate(
            cert,
            result,
        )

        return result

    # --------------------------------------------------
    # Parse Standard Certificate Fields
    # --------------------------------------------------

    def _parse_certificate(
        self,
        cert,
        result,
    ):

        subject = dict(

            item

            for group in cert.get(
                "subject",
                (),
            )

            for item in group

        )

        result.subject = subject.get(
            "commonName",
            "",
        )

        issuer = dict(

            item

            for group in cert.get(
                "issuer",
                (),
            )

            for item in group

        )

        result.issuer = issuer.get(
            "commonName",
            "",
        )

        result.valid_from = cert.get(
            "notBefore",
            "",
        )

        result.expires = cert.get(
            "notAfter",
            "",
        )

        if result.expires:

            expires = datetime.strptime(
                result.expires,
                "%b %d %H:%M:%S %Y %Z",
            ).replace(
                tzinfo=timezone.utc
            )

            now = datetime.now(
                timezone.utc
            )

            result.days_remaining = (
                expires - now
            ).days

            result.expired = (
                expires < now
            )

            result.expiration_warning = (
                0 <= result.days_remaining <= 30
            )

        result.self_signed = (
            result.subject == result.issuer
        )

        result.wildcard = (
            result.subject.startswith("*.")
        )

        for san in cert.get(
            "subjectAltName",
            (),
        ):

            if san[0] != "DNS":
                continue

            result.sans.append(
                san[1]
            )

            if san[1].startswith("*."):

                result.wildcard = True

        result.sans = sorted(
            set(result.sans)
        )