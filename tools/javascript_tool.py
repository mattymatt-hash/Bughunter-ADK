import hashlib
from pydoc import text

from config import settings
from models.javascript_file import JavaScriptFile
from tools.retry import http


class JavaScriptTool:

    JS_EXTENSIONS = (
        ".js",
        ".mjs",
        ".cjs",
    )

    JS_CONTENT_TYPES = (
        "application/javascript",
        "text/javascript",
        "application/x-javascript",
        "application/ecmascript",
        "text/ecmascript",
        "text/plain",
    )

    NON_JS_EXTENSIONS = (
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".svg",
        ".ico",
        ".webp",
        ".bmp",
        ".css",
        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".pdf",
        ".zip",
        ".gz",
        ".tar",
        ".7z",
        ".rar",
        ".mp4",
        ".mp3",
    )

    def scan(self, urls):

        results = []

        seen = set()

        for item in urls:

            url = item.url.strip()

            if url in seen:
                continue

            seen.add(url)

            #
            # Ignore obvious non-JS files before making a request
            #

            lower = url.lower().split("?", 1)[0]

            if lower.endswith(self.NON_JS_EXTENSIONS):
             continue
                

            try:

                response = http.get(url)

                if response is None:
                    continue

                if response.status_code != 200:
                    continue

                #
                # Validate MIME type
                #

                content_type = response.headers.get(
                    "Content-Type",
                    "",
                ).lower()

                text = response.text.lstrip().lower()

                if (
                    text.startswith("<!doctype html")
                    or text.startswith("<html")
                ):
                    continue

                if not any(
                    mime in content_type
                    for mime in self.JS_CONTENT_TYPES
                ):
                    continue

                #
                # Skip giant bundles
                #

                if (
                    len(response.content)
                    > settings.MAX_JS_FILE_SIZE
                ):
                    continue

                sha256 = hashlib.sha256(
                    response.content
                ).hexdigest()

                results.append(

                    JavaScriptFile(

                        url=url,

                        status=response.status_code,

                        content_type=content_type,

                        size=len(response.content),

                        sha256=sha256,

                    )

                )

            except Exception:

                continue

        return results