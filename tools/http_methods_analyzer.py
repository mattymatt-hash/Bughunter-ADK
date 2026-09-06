from models.http_method_result import HTTPMethodResult
from tools.retry import http


class HTTPMethodsAnalyzer:

    DANGEROUS = (
        "PUT",
        "DELETE",
        "TRACE",
        "CONNECT",
    )

    def analyze(self, url):

        result = HTTPMethodResult(host=url)

        try:

            response = http.options(
                url,
            )

            if response is None:
                return result

        except Exception:

            return result

        result.options_supported = True

        allow = response.headers.get(
            "Allow",
            "",
        )

        if not allow:

            allow = response.headers.get(
                "Access-Control-Allow-Methods",
                "",
            )

        methods = []

        for method in allow.split(","):

            method = method.strip().upper()

            if method:

                methods.append(method)

        result.methods = sorted(set(methods))

        result.dangerous = sorted(

            method
            for method in result.methods
            if method in self.DANGEROUS

        )

        return result