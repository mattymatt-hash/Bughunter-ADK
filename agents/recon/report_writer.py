import json
from pathlib import Path
from datetime import datetime


class ReportWriter:

    def save(self, result):

        Path("reports").mkdir(exist_ok=True)

        filename = datetime.now().strftime(
            "reports/report_%Y%m%d_%H%M%S.json"
        )

        with open(filename, "w", encoding="utf-8") as f:

            json.dump(result.__dict__, f, indent=4)

        return filename