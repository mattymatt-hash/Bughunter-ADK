import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path


class ReportWriter:

    def save(self, result):

        Path("reports").mkdir(exist_ok=True)

        filename = (
            f"reports/report_{datetime.now():%Y%m%d_%H%M%S}.json"
        )

        live_hosts = [h for h in result.hosts if h.status > 0]

        report = {
            "scan_time": datetime.now().isoformat(),
            "target": result.target,
            "ip": result.ip,
            "status": result.status,
            "title": result.title,
            "server": result.server,
            "robots": result.robots,
            "sitemap": result.sitemap,
            "technologies": result.technologies,

            "statistics": {
                "total_hosts": len(result.hosts),
                "live_hosts": len(live_hosts),
                "success": sum(
                    1 for h in live_hosts
                    if 200 <= h.status < 300
                ),
                "redirects": sum(
                    1 for h in live_hosts
                    if 300 <= h.status < 400
                ),
                "forbidden": sum(
                    1 for h in live_hosts
                    if h.status == 403
                ),
            },

            "hosts": [asdict(h) for h in result.hosts]
        }

        with open(filename, "w", encoding="utf-8") as f:

            json.dump(report, f, indent=4)

        return filename