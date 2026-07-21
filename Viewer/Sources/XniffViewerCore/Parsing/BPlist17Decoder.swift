import Foundation

/// A lossless, bounded decoder for the subset of Apple's undocumented
/// `bplist17` stream format observed in Foundation NSXPCConnection messages.
///
/// Unlike the object-table based `bplist00` format, bplist17 stores objects
/// inline and uses absolute byte offsets for references and container ends.
public enum BPlist17Decoder {
    private static let header = Data("bplist17".utf8)

    public static func decode(_ data: Data, sourceOffset: Int = 0) throws -> TraceValue {
        try decodeNested(data, sourceOffset: sourceOffset, embeddingDepth: 0)
    }

    fileprivate static func decodeNested(
        _ data: Data,
        sourceOffset: Int,
        embeddingDepth: Int
    ) throws -> TraceValue {
        guard data.starts(with: header) else {
            throw TraceParseError.invalidFile("Missing bplist17 header")
        }
        var parser = BPlist17Parser(
            data: data,
            sourceOffset: sourceOffset,
            embeddingDepth: embeddingDepth
        )
        let value = try parser.readRoot()
        return normalizeArchivedObjects(value)
    }

    public static func decodeIfPresent(_ data: Data, sourceOffset: Int = 0) -> TraceValue? {
        try? decode(data, sourceOffset: sourceOffset)
    }

    private static func normalizeArchivedObjects(_ value: TraceValue) -> TraceValue {
        switch value {
        case .sourced(let range, let nested):
            return .sourced(range: range, value: normalizeArchivedObjects(nested))
        case .array(let values):
            return .array(values.map(normalizeArchivedObjects))
        case .dictionary(let fields):
            let normalizedFields = fields.map {
                TraceField(name: $0.name, value: normalizeArchivedObjects($0.value), id: $0.id)
            }
            guard let className = normalizedFields.first(where: { $0.name == "$class" })?.value.stringValue else {
                return .dictionary(normalizedFields)
            }

            if className == "NSNull" {
                return .null
            }

            if ["NSDictionary", "NSMutableDictionary"].contains(className),
               let keys = normalizedFields.first(where: { $0.name == "NS.keys" })?.value.arrayValue,
               let values = normalizedFields.first(where: { $0.name == "NS.objects" })?.value.arrayValue {
                return .dictionary(zip(keys, values).map { key, value in
                    TraceField(name: key.summary, value: value)
                })
            }

            return .object(
                type: className,
                fields: normalizedFields.filter { $0.name != "$class" }
            )
        case .object(let type, let fields):
            return .object(type: type, fields: fields.map {
                TraceField(name: $0.name, value: normalizeArchivedObjects($0.value), id: $0.id)
            })
        case .data(let bytes, let interpretation):
            return .data(
                bytes,
                interpretation: interpretation.map(normalizeArchivedObjects)
            )
        default:
            return value
        }
    }
}

private struct BPlist17Parser {
    private let data: Data
    private let sourceOffset: Int
    private let embeddingDepth: Int
    private var activeOffsets: Set<Int> = []
    private let maximumDepth = 128

    init(data: Data, sourceOffset: Int, embeddingDepth: Int) {
        self.data = data
        self.sourceOffset = sourceOffset
        self.embeddingDepth = embeddingDepth
    }

    mutating func readRoot() throws -> TraceValue {
        try readObject(at: 8, depth: 0)
    }

    private mutating func readObject(at offset: Int, depth: Int) throws -> TraceValue {
        guard depth < maximumDepth else {
            return .error("Maximum bplist17 nesting depth reached")
        }
        guard !activeOffsets.contains(offset) else {
            return .reference(offset)
        }
        activeOffsets.insert(offset)
        defer { activeOffsets.remove(offset) }

        var reader = BinaryReader(data: data, offset: offset)
        return try readObject(&reader, depth: depth)
    }

    private mutating func readObject(
        _ reader: inout BinaryReader,
        depth: Int
    ) throws -> TraceValue {
        let objectStart = reader.offset
        let token = try reader.readUInt8()
        let type = token & 0xF0
        let inlineLength = Int(token & 0x0F)
        let value: TraceValue

        switch type {
        case 0x10:
            value = .signed(try readSignedInteger(&reader, count: inlineLength))
        case 0x20 where token == 0x22:
            value = .double(Double(Float(bitPattern: try reader.readUInt32())))
        case 0x20 where token == 0x23:
            value = .double(try reader.readDouble())
        case 0x40:
            let length = try readDynamicLength(&reader, inlineLength: inlineLength)
            let payloadStart = reader.offset
            let bytes = try reader.readData(count: length)
            value = .data(
                bytes,
                interpretation: interpretNestedData(bytes, payloadStart: payloadStart, depth: depth)
            )
        case 0x60:
            let characterCount = try readDynamicLength(&reader, inlineLength: inlineLength)
            guard characterCount <= reader.remaining / 2 else {
                throw TraceParseError.truncated(offset: reader.offset, wanted: characterCount * 2)
            }
            let bytes = try reader.readData(count: characterCount * 2)
            value = .string(String(data: bytes, encoding: .utf16LittleEndian) ?? String(decoding: bytes, as: UTF8.self))
        case 0x70:
            let length = try readDynamicLength(&reader, inlineLength: inlineLength)
            var bytes = try reader.readData(count: length)
            while bytes.last == 0 { bytes.removeLast() }
            value = .string(String(decoding: bytes, as: UTF8.self))
        case 0x80:
            let length = try readDynamicLength(&reader, inlineLength: inlineLength)
            let target = try readUnsignedInteger(&reader, count: length)
            guard target <= UInt64(Int.max), Int(target) >= 8, Int(target) < data.count else {
                throw TraceParseError.invalidFile(
                    String(format: "Invalid bplist17 reference 0x%llX at 0x%X", target, objectStart)
                )
            }
            value = try readObject(at: Int(target), depth: depth + 1)
        case 0xA0 where token == 0xA0:
            value = try readArray(&reader, depth: depth)
        case 0xB0 where token == 0xB0:
            value = .bool(true)
        case 0xC0 where token == 0xC0:
            value = .bool(false)
        case 0xD0 where token == 0xD0:
            value = try readDictionary(&reader, depth: depth)
        case 0xE0 where token == 0xE0:
            value = .null
        case 0xF0:
            value = .unsigned(try readUnsignedInteger(&reader, count: inlineLength))
        default:
            throw TraceParseError.unsupported(
                String(format: "Unsupported bplist17 token 0x%02X at 0x%X", token, objectStart)
            )
        }

        return .sourced(
            range: (sourceOffset + objectStart)..<(sourceOffset + reader.offset),
            value: value
        )
    }

    private mutating func readArray(
        _ reader: inout BinaryReader,
        depth: Int
    ) throws -> TraceValue {
        let end = try readContainerEnd(&reader)
        var values: [TraceValue] = []
        while reader.offset <= end {
            let childStart = reader.offset
            do {
                values.append(try readObject(&reader, depth: depth + 1))
            } catch {
                values.append(.sourced(
                    range: (sourceOffset + childStart)..<(sourceOffset + min(end + 1, data.count)),
                    value: .error(error.localizedDescription)
                ))
                reader.offset = end + 1
            }
            guard reader.offset > childStart else {
                throw TraceParseError.invalidFile("bplist17 array parser made no progress")
            }
        }
        guard reader.offset == end + 1 else {
            throw TraceParseError.invalidFile("bplist17 array exceeded its declared boundary")
        }
        return .array(values)
    }

    private mutating func readDictionary(
        _ reader: inout BinaryReader,
        depth: Int
    ) throws -> TraceValue {
        let end = try readContainerEnd(&reader)
        var fields: [TraceField] = []
        while reader.offset <= end {
            let pairStart = reader.offset
            do {
                let key = try readObject(&reader, depth: depth + 1)
                guard reader.offset <= end else {
                    throw TraceParseError.invalidFile("bplist17 dictionary is missing a value")
                }
                let value = try readObject(&reader, depth: depth + 1)
                fields.append(TraceField(name: key.fieldName, value: value))
            } catch {
                fields.append(TraceField(
                    name: String(format: "Decode stopped at 0x%X", pairStart),
                    value: .sourced(
                        range: (sourceOffset + pairStart)..<(sourceOffset + min(end + 1, data.count)),
                        value: .error(error.localizedDescription)
                    )
                ))
                reader.offset = end + 1
            }
            guard reader.offset > pairStart else {
                throw TraceParseError.invalidFile("bplist17 dictionary parser made no progress")
            }
        }
        guard reader.offset == end + 1 else {
            throw TraceParseError.invalidFile("bplist17 dictionary exceeded its declared boundary")
        }
        return .dictionary(fields)
    }

    private mutating func readContainerEnd(_ reader: inout BinaryReader) throws -> Int {
        let rawEnd = try reader.readUInt64()
        guard rawEnd <= UInt64(Int.max) else {
            throw TraceParseError.invalidFile("bplist17 container end exceeds addressable memory")
        }
        let end = Int(rawEnd)
        guard end >= reader.offset - 1, end < data.count else {
            throw TraceParseError.invalidFile(
                String(format: "Invalid bplist17 container end 0x%X", end)
            )
        }
        return end
    }

    private mutating func readDynamicLength(
        _ reader: inout BinaryReader,
        inlineLength: Int
    ) throws -> Int {
        guard inlineLength == 0xF else { return inlineLength }
        let lengthToken = try reader.readUInt8()
        guard lengthToken & 0xF0 == 0x10 else {
            throw TraceParseError.unsupported(
                String(format: "Unsupported bplist17 length token 0x%02X", lengthToken)
            )
        }
        let byteCount = Int(lengthToken & 0x0F)
        let length = try readUnsignedInteger(&reader, count: byteCount)
        guard length <= UInt64(Int.max) else {
            throw TraceParseError.invalidFile("bplist17 object length exceeds addressable memory")
        }
        return Int(length)
    }

    private mutating func readSignedInteger(
        _ reader: inout BinaryReader,
        count: Int
    ) throws -> Int64 {
        guard (0...8).contains(count) else {
            throw TraceParseError.unsupported("Unsupported \(count)-byte bplist17 integer")
        }
        guard count > 0 else { return 0 }
        let raw = try readUnsignedInteger(&reader, count: count)
        let shift = UInt64(64 - count * 8)
        return Int64(bitPattern: raw << shift) >> Int64(shift)
    }

    private mutating func readUnsignedInteger(
        _ reader: inout BinaryReader,
        count: Int
    ) throws -> UInt64 {
        guard (0...8).contains(count) else {
            throw TraceParseError.unsupported("Unsupported \(count)-byte bplist17 unsigned integer")
        }
        let bytes = try reader.readData(count: count)
        return bytes.enumerated().reduce(0) { result, element in
            result | (UInt64(element.element) << UInt64(element.offset * 8))
        }
    }

    private mutating func interpretNestedData(
        _ bytes: Data,
        payloadStart: Int,
        depth: Int
    ) -> TraceValue? {
        guard depth + 1 < maximumDepth else { return nil }
        let nestedSourceOffset = sourceOffset + payloadStart
        if bytes.starts(with: Data("bplist17".utf8)) {
            guard embeddingDepth < 16 else {
                return .error("Maximum embedded bplist17 depth reached")
            }
            return try? BPlist17Decoder.decodeNested(
                bytes,
                sourceOffset: nestedSourceOffset,
                embeddingDepth: embeddingDepth + 1
            )
        }
        if bytes.starts(with: Data("bplist00".utf8)) {
            if let archive = KeyedArchiveDecoder.decodeIfPresent(bytes) { return archive }
            var format = PropertyListSerialization.PropertyListFormat.binary
            if let plist = try? PropertyListSerialization.propertyList(from: bytes, options: [], format: &format) {
                return KeyedArchiveDecoder.propertyListValue(plist)
            }
        }
        return nil
    }
}

private extension TraceValue {
    var unwrappedValue: TraceValue {
        if case .sourced(_, let nested) = self { return nested.unwrappedValue }
        return self
    }

    var stringValue: String? {
        if case .string(let value) = unwrappedValue { return value }
        return nil
    }

    var arrayValue: [TraceValue]? {
        if case .array(let values) = unwrappedValue { return values }
        return nil
    }

    var fieldName: String {
        stringValue ?? summary
    }
}
