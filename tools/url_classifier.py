import os

from models.url_category import URLCategory


class URLClassifier:

    def classify(self, urls):

        results = []

        for item in urls:

            url = item.url.lower()

            if any(x in url for x in (
                "/api/",
                "/v1/",
                "/v2/",
                "/graphql",
                "/rest/",
            )):
                category = "API"

            elif any(x in url for x in (
                "login",
                "signin",
                "logon",
            )):
                category = "Login"

            elif any(x in url for x in (
                "admin",
                "administrator",
            )):
                category = "Admin"

            elif any(x in url for x in (
                "dashboard",
                "portal",
                "console",
            )):
                category = "Dashboard"

            elif any(x in url for x in (
                "oauth",
                "token",
                "auth",
                "authorize",
            )):
                category = "Auth"

            elif os.path.splitext(url)[1] in (
                ".js" ,
                ".css",
                ".map",
                ".woff",
                ".woff2",
                ".ttf",
            ):
                category = "Static"

            elif os.path.splitext(url)[1] in (
                ".png",
                ".jpg",
                ".jpeg",
                ".gif",
                ".svg",
                ".ico",
                ".webp",
            ):
                category = "Images"

            elif os.path.splitext(url)[1] in (
                ".zip",
                ".rar",
                ".7z",
                ".exe",
                ".apk",
                ".msi",
            ):  
                category = "Downloads"

            elif os.path.splitext(url)[1] in (
                ".pdf",
                ".doc",
                ".docx",
                ".xls",
                ".xlsx",
                ".ppt",
                ".pptx",
            ):
                category = "Documents"

            else:
                category = "Unknown"

            results.append(

                URLCategory(

                    category=category,

                    url=item.url,

                )

            )

        return results