from dataclasses import dataclass
from typing import Any, Optional

@dataclass
class BinaryNode:
    tag: str
    attrs: dict[str, str]
    content: Optional[list['BinaryNode'] | bytes | str] = None

    def __post_init__(self):
        if self.attrs is None:
            self.attrs = {}
