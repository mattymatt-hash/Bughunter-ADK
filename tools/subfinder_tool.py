import shutil
import subprocess
from pathlib import Path

from config import settings


class SubfinderTool:

    def __init__(self):

        candidate = Path.home() / "go" / "bin" / "subfinder.exe"

        if candidate.exists():

            self.subfinder = str(candidate)

        else:

            self.subfinder = shutil.which(
                "subfinder"
            )

        if self.subfinder is None:

            raise RuntimeError(
                "subfinder.exe not found.\n"
                "Install with:\n"
                "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
            )

    def scan(
        self,
        domain,
    ):

        command = [

            self.subfinder,

            "-silent",

            "-d",

            domain,

        ]

        if settings.SUBFINDER_RECURSIVE:

            command.append("-recursive")

        try:

            process = subprocess.run(

                command,

                capture_output=True,

                text=True,

                timeout=settings.SUBFINDER_TIMEOUT,

                check=False,

            )

        except subprocess.TimeoutExpired:

            print()
            print("========== SUBFINDER TIMEOUT ==========")
            print(
                f"Subfinder exceeded {settings.SUBFINDER_TIMEOUT} seconds."
            )
            print("=======================================")
            print()

            return []

        except Exception as e:

            print()
            print("========== SUBFINDER ERROR ==========")
            print(type(e).__name__)
            print(e)
            print("=====================================")
            print()

            return []

        if process.returncode != 0:

            print(process.stderr)

            return []

        results = sorted(

            set(

                line.strip()

                for line in process.stdout.splitlines()

                if line.strip()

            )

        )

        return results