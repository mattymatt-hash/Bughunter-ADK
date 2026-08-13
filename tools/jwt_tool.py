import base64
import json
from datetime import datetime, timezone

from models.jwt_result import JWTResult


class JWTTool:

    def _decode_base64url(self, value):

        padding = "=" * (-len(value) % 4)

        return base64.urlsafe_b64decode(
            value + padding
        )

    def decode(self, token, source=""):

        result = JWTResult()

        result.token = token

        result.source = source

        try:

            parts = token.split(".")

            if len(parts) != 3:
                return result

            header = json.loads(
                self._decode_base64url(parts[0])
            )

            payload = json.loads(
                self._decode_base64url(parts[1])
            )

            result.algorithm = header.get(
                "alg",
                "",
            )

            result.token_type = header.get(
                "typ",
                "",
            )

            result.issuer = payload.get(
                "iss",
                "",
            )

            result.subject = payload.get(
                "sub",
                "",
            )

            result.audience = str(
                payload.get(
                    "aud",
                    "",
                )
            )

            if "iat" in payload:

                result.issued_at = datetime.fromtimestamp(
                    payload["iat"],
                    tz=timezone.utc,
                ).isoformat()

            if "exp" in payload:

                exp = datetime.fromtimestamp(
                    payload["exp"],
                    tz=timezone.utc,
                )

                result.expires = exp.isoformat()

                result.expired = (
                    exp < datetime.now(timezone.utc)
                )

        except Exception:

            pass

        return result