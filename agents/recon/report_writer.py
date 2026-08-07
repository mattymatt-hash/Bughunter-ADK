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

        report = {

            "scan": {

                "profile": result.scan_profile,
                "started": result.started,
                "finished": result.finished,
                "duration_seconds": result.duration,

            },

            "target": {

                "domain": result.target,
                "ip": result.ip,
                "status": result.status,
                "title": result.title,
                "server": result.server,
                "powered_by": result.powered_by,
                "robots": result.robots,
                "sitemap": result.sitemap,

            },

            "statistics": {

                "discovered_hosts": result.discovered_hosts,
                "scanned_hosts": result.scanned_hosts,
                "live_hosts": result.live_hosts,

                "discovered_urls": result.discovered_urls,

                "2xx": result.success_2xx,
                "3xx": result.redirects_3xx,
                "403": result.forbidden_403,
                "404": result.not_found_404,
                "5xx": result.server_errors_5xx,

            },

            "technologies": result.technologies,

            "hosts": [

                asdict(host)

                for host in result.hosts

            ],

            "javascript_files": [

                asdict(js)

                for js in result.javascript_files

            ],

            "urls": [

                asdict(url)

                for url in result.urls

            ],
            "javascript_findings": [

              asdict(finding)

              for finding in result.javascript_findings

],
        }

        with open(filename, "w", encoding="utf-8") as f:

            json.dump(
                report,
                f,
                indent=4
            )

        return filename