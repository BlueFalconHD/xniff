import os
import struct
import tempfile
import unittest

from print_xpc import iter_events
from swift_xpc_codable import decode_swift_xpc_codable
from xpc_serialization import decode_xpc_serialization


SERIALIZED_DIAGNOSTIC = bytes.fromhex(
    "423713420500000000f000003800000002000000"
    "6b696e64000000000090000011000000786e6966662d646961676e6f7374696300"
    "0000007069640000300000af3e010000000000"
)


class XPCSerializationTests(unittest.TestCase):
    def test_decodes_private_libxpc_container(self):
        decoded = decode_xpc_serialization(SERIALIZED_DIAGNOSTIC)
        self.assertEqual(decoded["kind"], "xniff-diagnostic")
        self.assertEqual(decoded["pid"], 81583)

    def test_call_id_pairs_request_and_response(self):
        entry_header = struct.Struct("<IHHQ")
        fixed_header = struct.Struct("<IIQHHI")
        section_header = struct.Struct("<HHI")
        xpc_payload = struct.Struct("<IIIIQ8QIIII")

        def record(direction, sequence, reply=False):
            function = 5
            fixed = fixed_header.pack(99, 7, sequence, direction, 3, function)
            payload = xpc_payload.pack(3, direction, function, 0, 1 if reply else 0,
                                       *([0] * 8), 0, 0, 0, 0)
            call_section = section_header.pack(13, 0, 8) + struct.pack("<Q", 77)
            serialized_header = struct.pack("<BBHII", 2 if reply else 1, 1, 0,
                                            len(SERIALIZED_DIAGNOSTIC), len(SERIALIZED_DIAGNOSTIC))
            serialized_section = section_header.pack(7, 0, len(serialized_header) + len(SERIALIZED_DIAGNOSTIC))
            body = fixed + section_header.pack(10, 0, len(payload)) + payload + call_section
            body += serialized_section + serialized_header + SERIALIZED_DIAGNOSTIC
            return entry_header.pack(entry_header.size + len(body), 2, 1, sequence) + body

        with tempfile.NamedTemporaryFile(delete=False) as capture:
            path = capture.name
            capture.write(struct.pack("<IHH", 0x584E4246, 2, 0))
            capture.write(record(0, 1))
            capture.write(record(1, 2, reply=True))
        try:
            events = list(iter_events(path))
        finally:
            os.unlink(path)

        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["call_id"], events[1]["call_id"])
        self.assertEqual(events[0]["xpc"]["role"], "request")
        self.assertEqual(events[1]["xpc"]["role"], "response")
        self.assertIn("xniff-diagnostic", events[0]["xpc"]["serialized"]["message"]["pretty"])

    def test_decodes_swift_xpc_codable_graph(self):
        def string(tag, value):
            encoded = value.encode()
            return bytes([tag]) + struct.pack("<Q", len(encoded)) + encoded + b"\0"

        body = bytes([0x13, 0x0B, 0x0F]) + struct.pack("<Q", 41_300_000)
        body += bytes([0x14]) + struct.pack("<I", 0) + bytes([0x15, 0x13, 0x0A])
        body += string(0x11, "createSession")
        body += bytes([0x14]) + struct.pack("<I", 1) + bytes([0x15, 0x13, 0x0A])
        body += string(0x11, "name") + string(0x03, "hello")

        decoded = decode_swift_xpc_codable(body)
        self.assertEqual(decoded[0], 41_300_000)
        self.assertEqual(decoded[1]["createSession"]["name"], "hello")

    def test_resolves_swift_xpc_codable_object_reference(self):
        body = bytes([0x13, 0x0C, 0x06]) + struct.pack("<q", 0)
        decoded = decode_swift_xpc_codable(body, codable_objects=[{"secret": "resolved"}])
        self.assertEqual(decoded["$xpc_codable_object"]["value"]["secret"], "resolved")


if __name__ == "__main__":
    unittest.main()
