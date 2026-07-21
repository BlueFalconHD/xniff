import Foundation

public enum TraceParseError: LocalizedError, Sendable {
    case invalidFile(String)
    case truncated(offset: Int, wanted: Int)
    case unsupported(String)

    public var errorDescription: String? {
        switch self {
        case .invalidFile(let message): message
        case .truncated(let offset, let wanted):
            "Truncated dump at byte \(offset) (needed \(wanted) more bytes)"
        case .unsupported(let message): message
        }
    }
}

struct BinaryReader {
    let data: Data
    var offset: Int
    let end: Int

    init(data: Data, offset: Int = 0, end: Int? = nil) {
        self.data = data
        self.offset = offset
        self.end = end ?? data.count
    }

    var remaining: Int { end - offset }

    mutating func require(_ count: Int) throws {
        guard count >= 0, offset >= 0, offset + count <= end else {
            throw TraceParseError.truncated(offset: offset, wanted: count)
        }
    }

    mutating func readUInt8() throws -> UInt8 {
        try require(1)
        defer { offset += 1 }
        return data[offset]
    }

    mutating func readUInt16() throws -> UInt16 {
        try require(2)
        let value: UInt16 = data.withUnsafeBytes {
            $0.loadUnaligned(fromByteOffset: offset, as: UInt16.self)
        }
        offset += 2
        return UInt16(littleEndian: value)
    }

    mutating func readUInt32() throws -> UInt32 {
        try require(4)
        let value: UInt32 = data.withUnsafeBytes {
            $0.loadUnaligned(fromByteOffset: offset, as: UInt32.self)
        }
        offset += 4
        return UInt32(littleEndian: value)
    }

    mutating func readInt64() throws -> Int64 {
        Int64(bitPattern: try readUInt64())
    }

    mutating func readUInt64() throws -> UInt64 {
        try require(8)
        let value: UInt64 = data.withUnsafeBytes {
            $0.loadUnaligned(fromByteOffset: offset, as: UInt64.self)
        }
        offset += 8
        return UInt64(littleEndian: value)
    }

    mutating func readDouble() throws -> Double {
        Double(bitPattern: try readUInt64())
    }

    mutating func readData(count: Int) throws -> Data {
        try require(count)
        let value = data.subdata(in: offset..<(offset + count))
        offset += count
        return value
    }

    mutating func readString(count: Int) throws -> String {
        String(decoding: try readData(count: count), as: UTF8.self)
    }

    mutating func skip(_ count: Int) throws {
        try require(count)
        offset += count
    }

    mutating func align(to alignment: Int) throws {
        let aligned = (offset + alignment - 1) & ~(alignment - 1)
        try skip(aligned - offset)
    }
}
