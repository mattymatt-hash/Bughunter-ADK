import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path


class ReportWriter:

    def save(self, result):

        Path("reports").mkdir(exist_ok=True)

        filename = (
            f"reports/report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        )

        with open(filename, "w", encoding="utf-8") as f:
            json.dump(asdict(result), f, indent=4)

        return filename