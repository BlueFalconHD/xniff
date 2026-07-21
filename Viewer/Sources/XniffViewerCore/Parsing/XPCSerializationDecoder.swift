import Foundation

public enum XPCSerializationDecoder {
    public static func decode(_ data: Data) throws -> TraceValue {
        var reader = BinaryReader(data: data)
        guard data.count >= 8 else {
            throw TraceParseError.invalidFile("Truncated XPC serialization")
        }

        let first = try reader.readUInt32()
        let version = try reader.readUInt32()
        if first == 0x42133742 {
            guard version == 5 else {
                throw TraceParseError.unsupported("Unsupported XPC serialization version \(version)")
            }
        } else {
            let magic = Data([0x43, 0x50, 0x58, 0x40]) // CPX@
            guard data.prefix(4) == magic else {
                throw TraceParseError.invalidFile("Missing XPC serialization magic")
            }
            guard version == 5 else {
                throw TraceParseError.unsupported("Unsupported XPC serialization version \(version)")
            }
        }
        return try decodeObject(&reader)
    }

    private static func decodeObject(_ reader: inout BinaryReader) throws -> TraceValue {
        let rawType = try reader.readUInt32()
        guard rawType >= 0x1000 else {
            throw TraceParseError.invalidFile(String(format: "Invalid XPC type 0x%08x", rawType))
        }
        let type = (rawType - 0x1000) >> 12
        switch type {
        case 0x00:
            return .null
        case 0x01:
            return .bool(try reader.readUInt32() != 0)
        case 0x02:
            return .signed(try reader.readInt64())
        case 0x03:
            return .unsigned(try reader.readUInt64())
        case 0x04:
            return .double(try reader.readDouble())
        case 0x05:
            return .object(type: "Pointer", fields: [
                TraceField(name: "address", value: .string(String(format: "0x%llx", try reader.readUInt64())))
            ])
        case 0x06:
            return .object(type: "Date", fields: [
                TraceField(name: "raw", value: .unsigned(try reader.readUInt64()))
            ])
        case 0x07:
            let length = Int(try reader.readUInt32())
            return .data(try reader.readData(count: length))
        case 0x08:
            let length = Int(try reader.readUInt32())
            var bytes = try reader.readData(count: length)
            if bytes.last == 0 { bytes.removeLast() }
            return .string(String(decoding: bytes, as: UTF8.self))
        case 0x09:
            let bytes = [UInt8](try reader.readData(count: 16))
            let hex = bytes.enumerated().map { index, byte in
                let separator = [4, 6, 8, 10].contains(index) ? "-" : ""
                return separator + String(format: "%02x", byte)
            }.joined()
            return .object(type: "UUID", fields: [TraceField(name: "value", value: .string(hex))])
        case 0x0a, 0x0b, 0x0c:
            let name = type == 0x0a ? "File descriptor" : (type == 0x0b ? "Shared memory" : "Mach send right")
            return .object(type: name, fields: [
                TraceField(name: "value", value: .unsigned(UInt64(try reader.readUInt32())))
            ])
        case 0x0d, 0x0e:
            return try decodeContainer(type: type, reader: &reader)
        default:
            throw TraceParseError.unsupported(String(format: "Unsupported XPC type 0x%08x", rawType))
        }
    }

    private static func decodeContainer(type: UInt32, reader: inout BinaryReader) throws -> TraceValue {
        let totalBytes = Int(try reader.readUInt32())
        let count = Int(try reader.readUInt32())
        guard totalBytes >= 4 else {
            throw TraceParseError.invalidFile("Invalid XPC container length")
        }
        let containerEnd = reader.offset + totalBytes - 4
        guard containerEnd <= reader.end else {
            throw TraceParseError.invalidFile("Truncated XPC container")
        }

        if type == 0x0d {
            var values: [TraceValue] = []
            values.reserveCapacity(count)
            for _ in 0..<count where reader.offset < containerEnd {
                try reader.align(to: 4)
                values.append(try decodeObject(&reader))
            }
            reader.offset = containerEnd
            return .array(values)
        }

        var fields: [TraceField] = []
        fields.reserveCapacity(count)
        for _ in 0..<count where reader.offset < containerEnd {
            guard let nul = reader.data[reader.offset..<containerEnd].firstIndex(of: 0) else {
                throw TraceParseError.invalidFile("Unterminated XPC dictionary key")
            }
            let key = String(decoding: reader.data[reader.offset..<nul], as: UTF8.self)
            reader.offset = nul + 1
            try reader.align(to: 4)
            let value = try decodeObject(&reader)
            try reader.align(to: 4)
            fields.append(TraceField(name: key, value: value))
        }
        reader.offset = containerEnd
        return .dictionary(fields)
    }
}
