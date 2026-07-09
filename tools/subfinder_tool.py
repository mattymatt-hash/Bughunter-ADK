import shutil
import subprocess
from pathlib import Path


class SubfinderTool:

    def __init__(self):

        candidate = Path.home() / "go" / "bin" / "subfinder.exe"

        if candidate.exists():
            self.subfinder = str(candidate)
        else:
            self.subfinder = shutil.which("subfinder")

        if self.subfinder is None:
            raise RuntimeError(
                "subfinder.exe not found. Install it with:\n"
                "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
            )

    def scan(self, domain):

        command = [
            self.subfinder,
            "-silent",
            "-d",
            domain,
        ]

        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
        )

        if process.returncode != 0:
            raise RuntimeError(process.stderr)

        return [
            line.strip()
            for line in process.stdout.splitlines()
            if line.strip()
        ]