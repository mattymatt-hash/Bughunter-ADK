import json
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from config import settings

class ReportWriter:

    def save(self, result):

        Path("reports").mkdir(exist_ok=True)

        filename = (
            f"reports/report_{datetime.now():%Y%m%d_%H%M%S}.json"
        )

        report = {
            "scanner": {

                "name": settings.APP_NAME,

                "version": settings.VERSION,

            },

            "generated": datetime.now().isoformat(),
            
            # -----------------------------------
            # Scan Information
            # -----------------------------------

            "scan": {

                "profile": result.scan_profile,
                "started": result.started,
                "finished": result.finished,
                "duration_seconds": result.duration,

            },

            # -----------------------------------
            # Target
            # -----------------------------------

            "target": {

                "domain": result.target,
                "ip": result.ip,
                "status": result.status,
                "title": result.title,
                "server": result.server,
                "powered_by": result.powered_by,

                "robots": {

                    "found": result.robots.found,
                    "disallow": result.robots.disallow,
                    "allow": result.robots.allow,
                    "sitemaps": result.robots.sitemaps,
                    "interesting_paths": result.robots.interesting_paths,

                },

                "sitemap": {

                    "found": result.sitemap.found,
                    "urls": result.sitemap.urls,
                    "apis": result.sitemap.apis,
                    "images": result.sitemap.images,
                    "news": result.sitemap.news,
                    "alternate_languages": (
                        result.sitemap.alternate_languages
                    ),

                },

            },

            # -----------------------------------
            # Statistics
            # -----------------------------------

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

            "passive": {

                "wayback_urls": result.wayback_urls,

                "commoncrawl_urls": result.commoncrawl_urls,

                "otx_urls": result.otx_urls,

                "duplicates_removed": result.duplicate_urls,

                "unique_urls": len(result.urls),

            },

            # -----------------------------------
            # Technologies
            # -----------------------------------

            "technologies": result.technologies,

            # -----------------------------------
            # Hosts
            # -----------------------------------

            "hosts": [

                asdict(host)

                for host in result.hosts

            ],

            # -----------------------------------
            # JavaScript Files
            # -----------------------------------

            "javascript_files": [

                asdict(js)

                for js in result.javascript_files

            ],

            # -----------------------------------
            # URLs
            # -----------------------------------

            "urls": [

                asdict(url)

                for url in result.urls

            ],

            # -----------------------------------
            # JavaScript Findings
            # -----------------------------------

            "javascript_findings": [

                asdict(finding)

                for finding in result.javascript_findings

            ],

            # -----------------------------------
            # JWT Results
            # -----------------------------------

            "jwt_results": [

                asdict(jwt)

                for jwt in result.jwt_results

            ],

            # -----------------------------------
            # Security Headers
            # -----------------------------------

            "security_headers": [

                asdict(header)

                for header in result.header_results

            ],

            # -----------------------------------
            # TLS
            # -----------------------------------

            "tls": [

                asdict(tls)

                for tls in result.tls_results

            ],

            # -----------------------------------
            # HTTP Methods
            # -----------------------------------

            "http_methods": [

                asdict(item)

                for item in result.http_methods

            ],

        }

        with open(filename, "w", encoding="utf-8") as f:

            json.dump(
                report,
                f,
                indent=4,
            )

        return filename