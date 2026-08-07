from dataclasses import dataclass


@dataclass
class JavaScriptFinding:

    type: str
    value: str
    source: str