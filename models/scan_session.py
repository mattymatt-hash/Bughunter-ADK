from dataclasses import dataclass, field
from datetime import datetime

from models.scan_result import ScanResult


@dataclass
class ScanSession:

    profile: str = "quick"

    started: datetime = field(default_factory=datetime.now)

    finished: datetime | None = None

    duration: float = 0.0

    result: ScanResult | None = None