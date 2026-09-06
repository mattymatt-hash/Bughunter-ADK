import json
import shutil
import subprocess
from pathlib import Path

from config import settings


class HttpxTool:

    def __init__(self):

        candidate = Path.home() / "go" / "bin" / "httpx.exe"

        if candidate.exists():

            self.httpx = str(candidate)

        else:

            self.httpx = shutil.which("httpx")

        if self.httpx is None:

            raise RuntimeError(
                "httpx.exe not found"
            )

    def scan(self, target):

        command = [

            self.httpx,

            "-json",

            "-silent",

            "-tech-detect",

            "-title",

            "-status-code",

            "-server",

            "-follow-redirects",

            "-cdn",

            "-websocket",

        ]

        try:

            process = subprocess.run(

                command,

                input=target + "\n",

                text=True,

                capture_output=True,

                timeout=settings.REQUEST_TIMEOUT,

            )

        except subprocess.TimeoutExpired:

            return None

        except Exception:

            return None

        if process.returncode != 0:

            return None

        if not process.stdout.strip():

            return None

        try:

            return json.loads(
                process.stdout.splitlines()[0]
            )

        except Exception:

            return None