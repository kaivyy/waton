from dataclasses import dataclass


@dataclass
class BinaryNode:
    tag: str
    attrs: dict[str, str]
    content: list["BinaryNode"] | bytes | str | None = None

