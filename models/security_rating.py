from __future__ import annotations

SEVERITIES = ("info", "low", "medium", "high", "critical")


def clamp_confidence(value: float | int | None) -> float:
    try:
        return max(0.0, min(1.0, float(value if value is not None else 0.0)))
    except (TypeError, ValueError):
        return 0.0


def normalize_severity(value: str | None) -> str:
    value = str(value or "info").lower().strip()
    return value if value in SEVERITIES else "info"


def observation_severity(*, status: int = 0, has_query: bool = False, has_form: bool = False) -> str:
    """Severity for an observation, not a vulnerability claim."""
    if has_form and status >= 500:
        return "medium"
    if has_query or has_form:
        return "low"
    return "info"
