"""Decoder for libxpc's version-5 serialization container."""

from __future__ import annotations

import json
import struct
import uuid
from dataclasses import dataclass
from typing import Any

from swift_xpc_codable import SwiftXPCDecodeError, decode_swift_xpc_codable


class XPCDecodeError(ValueError):
    pass


@dataclass(frozen=True)
class _XPCData:
    value: bytes


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0

    def read(self, length: int) -> bytes:
        if length < 0 or self.offset + length > len(self.data):
            raise XPCDecodeError("truncated XPC serialization")
        value = self.data[self.offset : self.offset + length]
        self.offset += length
        return value

    def u32(self) -> int:
        return struct.unpack("<I", self.read(4))[0]

    def u64(self) -> int:
        return struct.unpack("<Q", self.read(8))[0]

    def align4(self) -> None:
        aligned = (self.offset + 3) & ~3
        self.read(aligned - self.offset)


def _decode_object(reader: _Reader) -> Any:
    raw_type = reader.u32()
    if raw_type < 0x1000:
        raise XPCDecodeError(f"invalid XPC type header 0x{raw_type:08x}")
    type_code = (raw_type - 0x1000) >> 12

    if type_code == 0x00:
        return None
    if type_code == 0x01:
        return reader.u32() != 0
    if type_code == 0x02:
        return struct.unpack("<q", reader.read(8))[0]
    if type_code == 0x03:
        return reader.u64()
    if type_code == 0x04:
        return struct.unpack("<d", reader.read(8))[0]
    if type_code == 0x05:
        return {"$pointer": f"0x{reader.u64():x}"}
    if type_code == 0x06:
        return {"$date": reader.u64()}
    if type_code == 0x07:
        length = reader.u32()
        return _XPCData(reader.read(length))
    if type_code == 0x08:
        length = reader.u32()
        value = reader.read(length)
        if value.endswith(b"\0"):
            value = value[:-1]
        return value.decode("utf-8", errors="replace")
    if type_code == 0x09:
        return {"$uuid": str(uuid.UUID(bytes=reader.read(16)))}
    if type_code in (0x0A, 0x0B, 0x0C):
        label = {0x0A: "$file", 0x0B: "$shmem", 0x0C: "$mach_send"}[type_code]
        return {label: reader.u32()}
    if type_code in (0x0D, 0x0E):
        total_bytes = reader.u32()
        count = reader.u32()
        if total_bytes < 4:
            raise XPCDecodeError("invalid XPC container length")
        container_end = reader.offset + total_bytes - 4
        if container_end > len(reader.data):
            raise XPCDecodeError("truncated XPC container")

        if type_code == 0x0D:
            result_array = []
            for _ in range(count):
                if reader.offset >= container_end:
                    break
                reader.align4()
                result_array.append(_decode_object(reader))
            reader.offset = container_end
            return result_array

        result_dict = {}
        for _ in range(count):
            if reader.offset >= container_end:
                break
            nul = reader.data.find(b"\0", reader.offset, container_end)
            if nul < 0:
                raise XPCDecodeError("unterminated XPC dictionary key")
            key = reader.data[reader.offset:nul].decode("utf-8", errors="replace")
            reader.offset = nul + 1
            reader.align4()
            result_dict[key] = _decode_object(reader)
            reader.align4()
        reader.offset = container_end
        return result_dict

    raise XPCDecodeError(f"unsupported XPC type header 0x{raw_type:08x}")


def decode_xpc_serialization(data: bytes) -> Any:
    reader = _Reader(data)
    if len(data) >= 8 and struct.unpack_from("<II", data, 0) == (0x42133742, 5):
        reader.offset = 8
        return _materialize(_decode_object(reader))
    if reader.read(4) != b"CPX@":
        raise XPCDecodeError("missing XPC serialization magic")
    version = reader.u32()
    if version != 5:
        raise XPCDecodeError(f"unsupported XPC serialization version {version}")
    return _materialize(_decode_object(reader))


def format_xpc_serialization(data: bytes) -> str:
    return json.dumps(decode_xpc_serialization(data), indent=2, ensure_ascii=False)


def _materialize(value: Any) -> Any:
    if isinstance(value, _XPCData):
        return _data_preview(value.value)
    if isinstance(value, list):
        return [_materialize(item) for item in value]
    if isinstance(value, dict):
        result = {key: _materialize(item) for key, item in value.items()}
        body = value.get("_CodableBody")
        version = value.get("_CodableCoderVersion")
        if isinstance(body, _XPCData) and version == 1:
            try:
                out_of_line = value.get("_CodableOutOfLine")
                if not isinstance(out_of_line, list):
                    out_of_line = []
                codable_objects = value.get("_CodableOutOfLine4CodableObject")
                if not isinstance(codable_objects, list):
                    codable_objects = []
                decoded = decode_swift_xpc_codable(
                    body.value,
                    out_of_line=out_of_line,
                    codable_objects=codable_objects,
                )
                result["_CodableBody"]["decoded"] = _materialize(decoded)
            except SwiftXPCDecodeError as exc:
                result["_CodableBody"]["decode_error"] = str(exc)
        return result
    return value


def _data_preview(value: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {"$data": value[:256].hex(), "length": len(value)}
    if len(value) > 256:
        result["preview_truncated"] = True
    return result
