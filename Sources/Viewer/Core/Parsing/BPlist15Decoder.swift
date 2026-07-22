import Foundation

/// Decodes CoreFoundation's inline `bplist15` property-list format.
///
/// A bplist15 stream contains a declared byte length, a five-byte reserved
/// field, and one recursively encoded root object. Bytes beyond the declared
/// length are transport padding and are intentionally ignored.
public enum BPlist15Decoder {
    private static let header = Data("bplist15".utf8)

    public static func decode(_ data: Data, sourceOffset: Int = 0) throws -> TraceValue {
        guard data.starts(with: header) else {
            throw TraceParseError.invalidFile("Missing bplist15 header")
        }
        var parser = BPlist15Parser(data: data, sourceOffset: sourceOffset)
        return try parser.readRoot()
    }

    public static func decodeIfPresent(_ data: Data, sourceOffset: Int = 0) -> TraceValue? {
        try? decode(data, sourceOffset: sourceOffset)
    }
}

private struct BPlist15Parser {
    private let data: Data
    private let sourceOffset: Int
    private let maximumDepth = 128
    private var reader: BinaryReader

    init(data: Data, sourceOffset: Int) {
        self.data = data
        self.sourceOffset = sourceOffset
        reader = BinaryReader(data: data, offset: 8)
    }

    mutating func readRoot() throws -> TraceValue {
        let declaredLength = try readDeclaredLength()
        guard declaredLength <= data.count else {
            throw TraceParseError.truncated(
                offset: data.count,
                wanted: declaredLength - data.count
            )
        }
        guard declaredLength > reader.offset else {
            throw TraceParseError.invalidFile("bplist15 has no root object")
        }

        reader = BinaryReader(data: data, offset: reader.offset, end: declaredLength)
        let value = try readObject(depth: 0)
        guard reader.offset == declaredLength else {
            throw TraceParseError.invalidFile(
                String(
                    format: "bplist15 root ended at 0x%X before declared end 0x%X", reader.offset,
                    declaredLength)
            )
        }
        return value
    }

    private mutating func readDeclaredLength() throws -> Int {
        let length = try readSignedIntegerObject()
        guard length >= 0, UInt64(length) <= UInt64(Int.max) else {
            throw TraceParseError.invalidFile("Invalid bplist15 declared length")
        }

        let reservedMarker = try reader.readUInt8()
        guard reservedMarker == 0x12 else {
            throw TraceParseError.invalidFile(
                String(format: "Invalid bplist15 reserved marker 0x%02X", reservedMarker)
            )
        }
        try reader.skip(4)
        return Int(length)
    }

    private mutating func readObject(depth: Int) throws -> TraceValue {
        guard depth < maximumDepth else {
            throw TraceParseError.invalidFile("Maximum bplist15 nesting depth reached")
        }

        let start = reader.offset
        let token = try reader.readUInt8()
        let type = token & 0xF0
        let inlineLength = Int(token & 0x0F)
        let value: TraceValue

        switch type {
        case 0x00:
            value = try readSimple(token: token, depth: depth)
        case 0x10:
            value = try readInteger(inlineLength: inlineLength)
        case 0x20:
            value = try readReal(token: token)
        case 0x30 where token == 0x33:
            let seconds = Double(bitPattern: try readBigEndianUInt64())
            value = .string(
                ISO8601DateFormatter().string(
                    from: Date(timeIntervalSinceReferenceDate: seconds)
                ))
        case 0x40:
            let length = try readLength(inlineLength: inlineLength)
            value = .data(try readData(count: length), interpretation: nil)
        case 0x50:
            let length = try readLength(inlineLength: inlineLength)
            value = .string(try readString(length: length, encoding: .ascii))
        case 0x60:
            let characterCount = try readLength(inlineLength: inlineLength)
            guard characterCount <= Int.max / 2 else {
                throw TraceParseError.invalidFile(
                    "bplist15 UTF-16 string length exceeds addressable memory")
            }
            let byteCount = characterCount * 2
            guard characterCount <= reader.remaining / 2 else {
                throw TraceParseError.truncated(offset: reader.offset, wanted: byteCount)
            }
            value = .string(
                try readString(
                    length: byteCount,
                    encoding: .utf16BigEndian
                ))
        case 0x70:
            let length = try readLength(inlineLength: inlineLength)
            value = .string(try readString(length: length, encoding: .utf8))
        case 0xA0:
            value = .array(
                try readValues(count: readLength(inlineLength: inlineLength), depth: depth))
        case 0xB0:
            value = collection(
                type: "Ordered set",
                values: try readValues(count: readLength(inlineLength: inlineLength), depth: depth)
            )
        case 0xC0:
            value = collection(
                type: "Set",
                values: try readValues(count: readLength(inlineLength: inlineLength), depth: depth)
            )
        case 0xD0:
            value = try readDictionary(count: readLength(inlineLength: inlineLength), depth: depth)
        default:
            throw TraceParseError.unsupported(
                String(format: "Unsupported bplist15 token 0x%02X at 0x%X", token, start)
            )
        }

        return .sourced(
            range: (sourceOffset + start)..<(sourceOffset + reader.offset),
            value: value
        )
    }

    private mutating func readSimple(token: UInt8, depth: Int) throws -> TraceValue {
        switch token {
        case 0x00:
            return .null
        case 0x08:
            return .bool(false)
        case 0x09:
            return .bool(true)
        case 0x0C:
            return .object(
                type: "URL",
                fields: [
                    TraceField(name: "Value", value: try readStringObject(depth: depth + 1))
                ])
        case 0x0D:
            let base = try readObject(depth: depth + 1)
            guard isURL(base) else {
                throw TraceParseError.invalidFile("bplist15 URL base is not a URL")
            }
            return .object(
                type: "URL",
                fields: [
                    TraceField(name: "Base", value: base),
                    TraceField(name: "Relative", value: try readStringObject(depth: depth + 1)),
                ])
        case 0x0E:
            return .object(
                type: "UUID",
                fields: [
                    TraceField(
                        name: "Value", value: .string(uuidString(try reader.readData(count: 16))))
                ])
        default:
            throw TraceParseError.unsupported(
                String(format: "Unsupported bplist15 simple token 0x%02X", token)
            )
        }
    }

    private mutating func readInteger(inlineLength: Int) throws -> TraceValue {
        guard inlineLength <= 4 else {
            throw TraceParseError.unsupported(
                "Unsupported bplist15 integer width marker \(inlineLength)")
        }
        if inlineLength == 4 {
            return .object(
                type: "128-bit integer",
                fields: [
                    TraceField(
                        name: "Encoded value",
                        value: .data(
                            try readData(count: 16),
                            interpretation: nil
                        ))
                ])
        }
        return .signed(try readBiasedInteger(byteCount: 1 << inlineLength))
    }

    private mutating func readReal(token: UInt8) throws -> TraceValue {
        switch token {
        case 0x22:
            return .double(Double(Float(bitPattern: try readBigEndianUInt32())))
        case 0x23:
            return .double(Double(bitPattern: try readBigEndianUInt64()))
        default:
            throw TraceParseError.unsupported(
                String(format: "Unsupported bplist15 real token 0x%02X", token)
            )
        }
    }

    private mutating func readLength(inlineLength: Int) throws -> Int {
        guard inlineLength == 0x0F else { return inlineLength }
        let length = try readSignedIntegerObject()
        guard length >= 0, UInt64(length) <= UInt64(Int.max) else {
            throw TraceParseError.invalidFile("Invalid bplist15 object length")
        }
        return Int(length)
    }

    private mutating func readSignedIntegerObject() throws -> Int64 {
        let tokenOffset = reader.offset
        let token = try reader.readUInt8()
        guard token & 0xF0 == 0x10 else {
            throw TraceParseError.invalidFile(
                String(
                    format: "Expected bplist15 integer at 0x%X, found 0x%02X", tokenOffset, token)
            )
        }
        let widthMarker = Int(token & 0x0F)
        guard widthMarker <= 3 else {
            throw TraceParseError.unsupported("Unsupported bplist15 length integer width")
        }
        return try readBiasedInteger(byteCount: 1 << widthMarker)
    }

    private mutating func readBiasedInteger(byteCount: Int) throws -> Int64 {
        let bytes = try reader.readData(count: byteCount)
        let encoded = bytes.enumerated().reduce(UInt64(0)) { result, element in
            result | (UInt64(element.element) << UInt64(element.offset * 8))
        }
        let bitCount = byteCount * 8
        let signBit = UInt64(1) << UInt64(bitCount - 1)
        let decoded = encoded ^ signBit
        if bitCount == 64 {
            return Int64(bitPattern: decoded)
        }
        if decoded & signBit != 0 {
            return Int64(bitPattern: decoded | (UInt64.max << UInt64(bitCount)))
        }
        return Int64(decoded)
    }

    private mutating func readValues(count: Int, depth: Int) throws -> [TraceValue] {
        guard count <= reader.remaining else {
            throw TraceParseError.invalidFile("bplist15 collection count exceeds remaining bytes")
        }
        var values: [TraceValue] = []
        values.reserveCapacity(count)
        for _ in 0..<count {
            values.append(try readObject(depth: depth + 1))
        }
        return values
    }

    private mutating func readDictionary(count: Int, depth: Int) throws -> TraceValue {
        guard count <= reader.remaining / 2 else {
            throw TraceParseError.invalidFile("bplist15 dictionary count exceeds remaining bytes")
        }
        let keys = try readValues(count: count, depth: depth)
        let values = try readValues(count: count, depth: depth)
        return .dictionary(
            zip(keys, values).map { key, value in
                TraceField(name: fieldName(key), value: value)
            })
    }

    private mutating func readStringObject(depth: Int) throws -> TraceValue {
        let value = try readObject(depth: depth)
        guard stringValue(value) != nil else {
            throw TraceParseError.invalidFile("bplist15 URL component is not a string")
        }
        return value
    }

    private mutating func readString(length: Int, encoding: String.Encoding) throws -> String {
        let bytes = try readData(count: length)
        guard let value = String(data: bytes, encoding: encoding) else {
            throw TraceParseError.invalidFile("Invalid bplist15 string encoding")
        }
        return value
    }

    private mutating func readBigEndianUInt32() throws -> UInt32 {
        try reader.readData(count: 4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
    }

    private mutating func readBigEndianUInt64() throws -> UInt64 {
        try reader.readData(count: 8).reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
    }

    private mutating func readData(count: Int) throws -> Data {
        guard count <= reader.remaining else {
            throw TraceParseError.truncated(offset: reader.offset, wanted: count)
        }
        return try reader.readData(count: count)
    }

    private func collection(type: String, values: [TraceValue]) -> TraceValue {
        .object(
            type: type,
            fields: values.enumerated().map {
                TraceField(name: "Item \($0.offset)", value: $0.element)
            })
    }

    private func fieldName(_ value: TraceValue) -> String {
        stringValue(value) ?? value.summary
    }

    private func stringValue(_ value: TraceValue) -> String? {
        if case .sourced(_, let nested) = value { return stringValue(nested) }
        if case .string(let string) = value { return string }
        return nil
    }

    private func isURL(_ value: TraceValue) -> Bool {
        if case .sourced(_, let nested) = value { return isURL(nested) }
        if case .object(let type, _) = value { return type == "URL" }
        return false
    }

    private func uuidString(_ data: Data) -> String {
        let hex = data.map { String(format: "%02X", $0) }.joined()
        guard hex.count == 32 else { return hex }
        let boundaries = [8, 12, 16, 20]
        var result = ""
        for (index, character) in hex.enumerated() {
            if boundaries.contains(index) { result.append("-") }
            result.append(character)
        }
        return result
    }
}
