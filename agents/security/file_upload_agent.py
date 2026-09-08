from __future__ import annotations

from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

from agents.base_agent import BaseSecurityAgent
from models.agent_result import AgentResult
from models.hypothesis import Hypothesis


class FileUploadAgent(BaseSecurityAgent):
    name = "file_upload"
    description = (
        "Analyzes discovered file upload and file-processing surfaces "
        "for potential security risks."
    )

    UPLOAD_PATH_INDICATORS = (
        "/upload",
        "/uploads",
        "/file-upload",
        "/fileupload",
        "/attachment",
        "/attachments",
        "/import",
        "/media",
        "/avatar",
        "/images",
        "/documents",
    )

    def run(
        self,
        scan_result: Any,
        target_profile: Any,
        context: dict[str, Any] | None = None,
    ) -> AgentResult:

        target = (
            getattr(scan_result, "target", None)
            or getattr(target_profile, "target", None)
            or "unknown"
        )

        result = AgentResult(
            agent=self.name,
            target=target,
            metadata={
                "phase": 3,
                "implemented": True,
                "analysis_type": "recon_driven",
                "destructive_testing": False,
            },
        )

        surfaces: list[dict[str, Any]] = []

        profile_uploads = (
            getattr(target_profile, "upload_endpoints", [])
            or []
        )

        for endpoint in profile_uploads:
            if endpoint:
                surfaces.append(
                    {
                        "url": endpoint,
                        "source": "target_profile",
                    }
                )

                result.add_observation(
                    {
                        "type": "file_upload_endpoint",
                        "source_url": endpoint,
                        "message": (
                            "A file upload endpoint was identified "
                            "in the target profile."
                        ),
                        "severity": "medium",
                        "confidence": 0.90,
                    }
                )

        for url in self._get_urls(scan_result, target_profile):
            parsed = urlparse(url)
            path = parsed.path.lower()

            indicators = [
                indicator
                for indicator in self.UPLOAD_PATH_INDICATORS
                if indicator in path
            ]

            if indicators:
                existing = any(
                    surface.get("url") == url
                    for surface in surfaces
                )

                if not existing:
                    surfaces.append(
                        {
                            "url": url,
                            "source": "url_analysis",
                            "indicators": indicators,
                        }
                    )

                result.add_observation(
                    {
                        "type": "file_processing_surface",
                        "source_url": url,
                        "indicators": indicators,
                        "message": (
                            "The endpoint path contains indicators "
                            "associated with file upload or processing."
                        ),
                        "severity": "medium",
                        "confidence": 0.70,
                    }
                )

        upload_present = getattr(
            target_profile,
            "file_upload_present",
            False,
        )

        if upload_present:
            result.add_observation(
                {
                    "type": "file_upload_capability",
                    "source_url": target,
                    "message": (
                        "The target profile indicates that file upload "
                        "functionality is present."
                    ),
                    "severity": "medium",
                    "confidence": 0.90,
                }
            )

        result.add_observation(
            {
                "type": "file_upload_surface",
                "source_url": target,
                "surface_count": len(surfaces),
                "upload_capability": upload_present,
                "message": (
                    f"{len(surfaces)} potential file upload or "
                    "file-processing surface(s) were identified."
                ),
                "severity": "info",
                "confidence": 0.90,
            }
        )

        if surfaces or upload_present:
            hypotheses = [
                (
                    "file_upload_validation",
                    "Review uploaded-file type and content validation.",
                    "high",
                ),
                (
                    "file_upload_storage",
                    "Review storage and serving behavior for uploaded files.",
                    "high",
                ),
                (
                    "file_upload_access_control",
                    "Review authorization boundaries around uploaded files.",
                    "high",
                ),
                (
                    "file_processing",
                    "Review server-side processing of uploaded or imported files.",
                    "medium",
                ),
            ]

            for vulnerability_type, description, priority in hypotheses:
                hypothesis = Hypothesis(
                    id=f"{self.name}-{uuid4().hex[:12]}",
                    agent=self.name,
                    vulnerability_type=vulnerability_type,
                    target=target,
                    description=description,
                    confidence=0.70,
                    priority=priority,
                    status="pending",
                    metadata={
                        "phase": 3,
                        "upload_surfaces": surfaces,
                    },
                )

                result.add_hypothesis(hypothesis)

        result.metadata.update(
            {
                "surface_count": len(surfaces),
                "upload_capability": upload_present,
                "hypothesis_count": len(result.hypotheses),
                "observation_count": len(result.observations),
            }
        )

        return result

    def _get_urls(
        self,
        scan_result: Any,
        target_profile: Any,
    ) -> list[str]:

        urls: list[str] = []

        for item in getattr(scan_result, "urls", []) or []:
            url = getattr(item, "url", None)

            if url and url not in urls:
                urls.append(url)

        for url in getattr(target_profile, "endpoints", []) or []:
            if url and url not in urls:
                urls.append(url)

        return urls