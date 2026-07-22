"""Decoder for libSwiftXPC's version-1 serialized Codable graph."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Any, Sequence


class SwiftXPCDecodeError(ValueError):
    pass


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0

    def read(self, length: int) -> bytes:
        if length < 0 or self.offset + length > len(self.data):
            raise SwiftXPCDecodeError(f"truncated Swift XPC graph at byte {self.offset}")
        value = self.data[self.offset : self.offset + length]
        self.offset += length
        return value

    def unpack(self, format_: str) -> Any:
        size = struct.calcsize(format_)
        return struct.unpack(format_, self.read(size))[0]

    def string(self) -> str:
        length = self.unpack("<Q")
        value = self.read(length + 1)
        if not value.endswith(b"\0"):
            raise SwiftXPCDecodeError("Swift XPC string is missing its terminator")
        return value[:-1].decode("utf-8", errors="replace")


@dataclass(frozen=True)
class _Token:
    kind: str
    value: Any = None
    tag: int = -1


def _parse(data: bytes) -> tuple[list[_Token], dict[int, list[_Token]]]:
    reader = _Reader(data)
    root: list[_Token] = []
    nodes: dict[int, list[_Token]] = {}
    pending: set[int] = set()
    current_id: int | None = None
    current: list[_Token] = []
    next_id = 0

    while reader.offset < len(data):
        tag = reader.read(1)[0]
        if tag == 0:
            token = _Token("value", None, tag)
        elif tag in (1, 2):
            token = _Token("value", tag == 1, tag)
        elif tag == 3:
            token = _Token("value", reader.string(), tag)
        elif tag == 4:
            token = _Token("value", reader.unpack("<f"), tag)
        elif tag == 5:
            token = _Token("value", reader.unpack("<d"), tag)
        elif tag in (6, 10):
            token = _Token("value", reader.unpack("<q"), tag)
        elif tag == 7:
            token = _Token("value", reader.unpack("<b"), tag)
        elif tag == 8:
            token = _Token("value", reader.unpack("<h"), tag)
        elif tag == 9:
            token = _Token("value", reader.unpack("<i"), tag)
        elif tag in (11, 15):
            token = _Token("value", reader.unpack("<Q"), tag)
        elif tag == 12:
            token = _Token("value", reader.unpack("<B"), tag)
        elif tag == 13:
            token = _Token("value", reader.unpack("<H"), tag)
        elif tag == 14:
            token = _Token("value", reader.unpack("<I"), tag)
        elif tag == 16:
            token = _Token("key", None, tag)
        elif tag == 17:
            token = _Token("key", reader.string(), tag)
        elif tag == 18:
            token = _Token("out_of_line", reader.unpack("<I"), tag)
        elif tag == 19:
            metadata = reader.unpack("<B")
            if metadata not in (10, 11, 12):
                raise SwiftXPCDecodeError(f"invalid container metadata 0x{metadata:02x}")
            token = _Token("metadata", metadata, tag)
        elif tag == 20:
            identifier = reader.unpack("<I")
            if identifier in pending or identifier in nodes:
                raise SwiftXPCDecodeError(f"duplicate container reference {identifier}")
            pending.add(identifier)
            token = _Token("reference", identifier, tag)
        elif tag == 21:
            if current_id is None:
                root = current
            else:
                nodes[current_id] = current
            if next_id not in pending:
                raise SwiftXPCDecodeError("insufficient container transition")
            pending.remove(next_id)
            current_id = next_id
            next_id += 1
            current = []
            continue
        elif tag == 22:
            raise SwiftXPCDecodeError("graph ended with a dangling container")
        else:
            raise SwiftXPCDecodeError(f"unsupported graph tag 0x{tag:02x}")
        current.append(token)

    if current_id is None:
        root = current
    else:
        nodes[current_id] = current
    if pending:
        raise SwiftXPCDecodeError("graph contains dangling container references")
    return root, nodes


def decode_swift_xpc_codable(
    data: bytes,
    *,
    out_of_line: Sequence[Any] = (),
    codable_objects: Sequence[Any] = (),
) -> Any:
    root, nodes = _parse(data)
    codable_references = _unambiguous_codable_references(root, nodes, len(codable_objects))

    def render_token(token: _Token, visiting: frozenset[int]) -> Any:
        if token.kind == "value":
            return token.value
        if token.kind == "key":
            return token.value if token.value is not None else "<nil key>"
        if token.kind == "out_of_line":
            index = token.value
            if index >= len(out_of_line):
                return {"$error": f"invalid Swift XPC out-of-line index {index}"}
            return {"$xpc_data": {"index": index, "value": out_of_line[index]}}
        if token.kind == "reference":
            identifier = token.value
            if identifier in visiting:
                return {"$error": f"cyclic Swift XPC container reference {identifier}"}
            if identifier not in nodes:
                return {"$error": f"missing Swift XPC container {identifier}"}
            return render_container(nodes[identifier], visiting | {identifier})
        return token.value

    def render_container(tokens: list[_Token], visiting: frozenset[int]) -> Any:
        metadata = next((token.value for token in tokens if token.kind == "metadata"), None)
        values = [token for token in tokens if token.kind != "metadata"]
        if (
            metadata == 12
            and len(values) == 1
            and values[0].kind == "value"
            and values[0].tag == 6
            and values[0].value in codable_references
        ):
            index = values[0].value
            return {"$xpc_codable_object": {"index": index, "value": codable_objects[index]}}
        if metadata == 10:
            result: dict[str, Any] = {}
            index = 0
            while index < len(values):
                key_token = values[index]
                if key_token.kind != "key":
                    result[f"$malformed_{index}"] = render_token(key_token, visiting)
                    index += 1
                    continue
                key = key_token.value if key_token.value is not None else "<nil key>"
                if index + 1 >= len(values):
                    result[key] = {"$error": "missing keyed value"}
                    break
                result[key] = render_token(values[index + 1], visiting)
                index += 2
            return result
        rendered = [render_token(token, visiting) for token in values]
        if metadata == 12 or metadata is None:
            return rendered[0] if len(rendered) == 1 else rendered
        return rendered

    return render_container(root, frozenset())


def _unambiguous_codable_references(
    root: list[_Token],
    nodes: dict[int, list[_Token]],
    object_count: int,
) -> set[int]:
    counts: dict[int, int] = {}
    if object_count == 0:
        return set()
    for tokens in [root, *nodes.values()]:
        metadata = next((token.value for token in tokens if token.kind == "metadata"), None)
        values = [token for token in tokens if token.kind != "metadata"]
        if (
            metadata == 12
            and len(values) == 1
            and values[0].kind == "value"
            and values[0].tag == 6
            and isinstance(values[0].value, int)
            and 0 <= values[0].value < object_count
        ):
            counts[values[0].value] = counts.get(values[0].value, 0) + 1
    return {index for index, count in counts.items() if count == 1}
