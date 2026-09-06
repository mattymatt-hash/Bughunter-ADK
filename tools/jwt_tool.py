import base64
import json
from datetime import datetime, timezone
from math import exp
from unittest import result


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

            parts = token.strip().split(".")

            if len(parts) != 3:
                return result

            header = json.loads(
                self._decode_base64url(parts[0])
            )

            payload = json.loads(
                self._decode_base64url(parts[1])
            )

            result.header = header

            result.payload = payload

            result.algorithm = header.get(
                "alg",
                "",
            )

            result.algorithm_none = (
                result.algorithm.lower() == "none"
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

            result.jwt_id = payload.get(
                "jti",
                "",
            )

            result.scope = payload.get(
                "scope",
                "",
            )

            result.roles = payload.get(
                "roles",
                []
            )

            result.email = payload.get(
                "email",
                "",
            )

            result.weak_algorithm = (
                result.algorithm.upper() == "NONE"
            )

            if "iat" in payload:

                result.issued_at = datetime.fromtimestamp(
                    payload["iat"],
                    tz=timezone.utc,
                ).isoformat()

            result.has_expiration = (
                "exp" in payload
            )

            if "exp" in payload:

                exp = datetime.fromtimestamp(
                    payload["exp"],
                    tz=timezone.utc,
                )

                result.expires = exp.isoformat()

                result.expired = (
                    exp < datetime.now(timezone.utc)
                )

                if "iat" in payload:

                    issued = datetime.fromtimestamp(
                        payload["iat"],
                        tz=timezone.utc,
                    )

                    lifetime = (
                        exp - issued
                    ).total_seconds()

                    result.lifetime_hours = (
                        lifetime / 3600
                    )

                    result.long_lived = (
                        lifetime > 86400
                    )


        except Exception as e:

            result.error = str(e)

        return result