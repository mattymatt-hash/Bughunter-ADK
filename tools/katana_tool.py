import shutil
import subprocess

from config import settings
from models.url_result import UrlResult


class KatanaTool:

    def __init__(self):

        self.binary = shutil.which("katana")

        if self.binary is None:

            raise RuntimeError(
                "Katana was not found in PATH.\n"
                "Install it with:\n"
                "go install github.com/projectdiscovery/katana/cmd/katana@latest"
            )

    def scan(
        self,
        target,
        depth=settings.KATANA_DEPTH,
        concurrency=settings.KATANA_CONCURRENCY,
        timeout=settings.KATANA_TIMEOUT,
    ):

        command = [

            self.binary,

            "-u",
            target,

            "-silent",

            "-d",
            str(depth),

            "-c",
            str(concurrency),

        ]

        try:

            process = subprocess.run(

                command,

                capture_output=True,

                text=True,

                encoding="utf-8",

                timeout=timeout,

                check=False,

            )

        except subprocess.TimeoutExpired:

            print()
            print("========== KATANA TIMEOUT ==========")
            print(f"Katana exceeded {timeout} seconds.")
            print("====================================")
            print()

            return []

        except Exception as e:

            print()
            print("========== KATANA ERROR ==========")
            print(type(e).__name__)
            print(e)
            print("==================================")
            print()

            return []

        results = []

        seen = set()

        for line in process.stdout.splitlines():

            url = line.strip()

            if not url:
                continue

            if not (
                url.startswith("http://")
                or url.startswith("https://")
            ):
                continue

            if url in seen:
                continue

            seen.add(url)

            results.append(

                UrlResult(

                    url=url,

                    status=0,

                    content_type="",

                    source="katana",

                    length=0,

                )

            )

        return results