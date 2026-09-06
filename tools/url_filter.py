from urllib.parse import urlsplit


class URLFilter:

    #
    # File extensions that are usually not useful
    #

    IGNORE_EXTENSIONS = (

        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".bmp",
        ".svg",
        ".ico",
        ".webp",

        ".css",

        ".woff",
        ".woff2",
        ".ttf",
        ".eot",
        ".otf",

        ".mp3",
        ".wav",
        ".ogg",

        ".mp4",
        ".avi",
        ".mov",
        ".wmv",
        ".webm",

        ".zip",
        ".rar",
        ".7z",

        ".pdf",

    )

    #
    # High-value paths
    #

    HIGH_PRIORITY = (

        "/admin",
        "/login",
        "/signin",
        "/auth",
        "/oauth",
        "/register",

        "/api",
        "/graphql",
        "/swagger",
        "/openapi",

        "/dashboard",

        "/debug",

        "/health",

        "/metrics",

        "/config",

        "/backup",

        "/uploads",

        "/upload",

        "/private",

        "/internal",

        "/console",

        "/actuator",

        "/jenkins",

        "/grafana",

        "/prometheus",

        "/kibana",

    )

    def interesting(
        self,
        url,
    ):

        path = urlsplit(url).path.lower()

        return not path.endswith(
            self.IGNORE_EXTENSIONS
        )

    def high_priority(
        self,
        url,
    ):

        path = urlsplit(url).path.lower()

        return any(

            item in path

            for item in self.HIGH_PRIORITY

        )