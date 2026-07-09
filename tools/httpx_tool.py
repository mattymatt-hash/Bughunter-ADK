import json
import shutil
import subprocess
from pathlib import Path


class HttpxTool:

    def __init__(self):

        # Prefer the Go installation
        candidate = Path.home() / "go" / "bin" / "httpx.exe"

        if candidate.exists():
            self.httpx = str(candidate)
        else:
            self.httpx = shutil.which("httpx")

        if self.httpx is None:
            raise RuntimeError(
                "httpx.exe not found. Install it with:\n"
                "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
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
        ]

       
        process = subprocess.run(
            command,
            input=target + "\n",
            text=True,
            capture_output=True,
        )


        if process.returncode != 0:
            raise RuntimeError(
                f"httpx exited with code {process.returncode}"
            )

        if not process.stdout.strip():
            raise RuntimeError("httpx returned no output")

        return json.loads(process.stdout.splitlines()[0])