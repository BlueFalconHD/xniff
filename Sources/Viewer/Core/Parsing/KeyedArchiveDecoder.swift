import CoreFoundation
import Darwin
import Foundation

public enum KeyedArchiveDecoder {
    private typealias UIDGetTypeID = @convention(c) () -> CFTypeID
    private typealias UIDGetValue = @convention(c) (CFTypeRef) -> CFIndex

    private struct UIDFunctions: @unchecked Sendable {
        let getTypeID: UIDGetTypeID
        let getValue: UIDGetValue
    }

    private static let uidFunctions: UIDFunctions? = {
        guard let handle = dlopen(nil, RTLD_LAZY),
              let typeSymbol = dlsym(handle, "_CFKeyedArchiverUIDGetTypeID"),
              let valueSymbol = dlsym(handle, "_CFKeyedArchiverUIDGetValue") else {
            return nil
        }
        return UIDFunctions(
            getTypeID: unsafeBitCast(typeSymbol, to: UIDGetTypeID.self),
            getValue: unsafeBitCast(valueSymbol, to: UIDGetValue.self)
        )
    }()

    public static func decode(_ data: Data) throws -> TraceValue {
        var format = PropertyListSerialization.PropertyListFormat.binary
        let propertyList = try PropertyListSerialization.propertyList(
            from: data,
            options: [],
            format: &format
        )
        guard let root = dictionary(propertyList),
              root["$archiver"] as? String == "NSKeyedArchiver",
              let objects = root["$objects"] as? [Any],
              let top = dictionary(root["$top"] as Any) else {
            throw TraceParseError.invalidFile("Payload is not an NSKeyedArchiver archive")
        }

        let rootReference = top["root"] ?? top.values.first
        guard let rootReference else {
            throw TraceParseError.invalidFile("NSKeyedArchiver archive has no root object")
        }
        var resolver = ArchiveResolver(objects: objects)
        return resolver.resolve(rootReference, depth: 0)
    }

    public static func decodeIfPresent(_ data: Data) -> TraceValue? {
        try? decode(data)
    }

    static func propertyListValue(_ value: Any, depth: Int = 0) -> TraceValue {
        guard depth < 128 else { return .error("Maximum nesting depth reached") }
        if let value = value as? String { return .string(value) }
        if let value = value as? Data { return .data(value, interpretation: nil) }
        if let value = value as? Date { return .string(ISO8601DateFormatter().string(from: value)) }
        if let value = value as? NSNumber {
            return numberValue(value)
        }
        if let values = value as? [Any] {
            return .array(values.map { propertyListValue($0, depth: depth + 1) })
        }
        if let fields = dictionary(value) {
            return .dictionary(fields.keys.sorted().map {
                TraceField(name: $0, value: propertyListValue(fields[$0] as Any, depth: depth + 1))
            })
        }
        return .string(String(describing: value))
    }

    private static func dictionary(_ value: Any) -> [String: Any]? {
        if let dictionary = value as? [String: Any] { return dictionary }
        guard let dictionary = value as? [AnyHashable: Any] else { return nil }
        return Dictionary(uniqueKeysWithValues: dictionary.map { (String(describing: $0.key), $0.value) })
    }

    fileprivate static func uidValue(_ value: Any) -> Int? {
        if let dictionary = dictionary(value), let number = dictionary["CF$UID"] as? NSNumber {
            return number.intValue
        }

        guard let uidFunctions else {
            return uidFromDescription(value)
        }
        let object = value as AnyObject
        let cfObject = unsafeBitCast(object, to: CFTypeRef.self)
        guard CFGetTypeID(cfObject) == uidFunctions.getTypeID() else { return nil }
        return uidFunctions.getValue(cfObject)
    }

    fileprivate static func numberValue(_ value: NSNumber) -> TraceValue {
        if CFGetTypeID(value) == CFBooleanGetTypeID() { return .bool(value.boolValue) }
        let encoding = String(cString: value.objCType)
        if encoding == "f" || encoding == "d" { return .double(value.doubleValue) }
        if ["C", "S", "I", "L", "Q"].contains(encoding) {
            return .unsigned(value.uint64Value)
        }
        return .signed(value.int64Value)
    }

    private static func uidFromDescription(_ value: Any) -> Int? {
        let description = String(describing: value)
        guard let range = description.range(of: #"value = \d+"#, options: .regularExpression) else {
            return nil
        }
        return Int(description[range].dropFirst("value = ".count))
    }
}

private struct ArchiveResolver {
    let objects: [Any]
    var active: Set<Int> = []

    mutating func resolve(_ value: Any, depth: Int) -> TraceValue {
        guard depth < 128 else { return .error("Maximum archive nesting depth reached") }
        if let index = KeyedArchiveDecoder.uidValue(value) {
            guard objects.indices.contains(index) else { return .error("Invalid archive reference \(index)") }
            if active.contains(index) { return .reference(index) }
            active.insert(index)
            defer { active.remove(index) }
            return resolveObject(objects[index], index: index, depth: depth + 1)
        }
        return convert(value, depth: depth)
    }

    private mutating func resolveObject(_ value: Any, index: Int, depth: Int) -> TraceValue {
        if let string = value as? String, string == "$null" { return .null }
        guard let fields = archiveDictionary(value) else { return convert(value, depth: depth) }
        let className = className(for: fields["$class"])

        switch className {
        case "NSNull":
            return .null
        case "NSDictionary", "NSMutableDictionary":
            let keys = fields["NS.keys"] as? [Any] ?? []
            let values = fields["NS.objects"] as? [Any] ?? []
            return .dictionary(zip(keys, values).map { key, value in
                let decodedKey = resolve(key, depth: depth + 1)
                return TraceField(name: decodedKey.summary, value: resolve(value, depth: depth + 1))
            })
        case "NSArray", "NSMutableArray", "NSSet", "NSMutableSet", "NSOrderedSet":
            let values = fields["NS.objects"] as? [Any] ?? []
            return .array(values.map { resolve($0, depth: depth + 1) })
        case "NSData", "NSMutableData":
            if let data = fields["NS.data"] as? Data { return .data(data, interpretation: nil) }
        case "NSDate":
            if let seconds = fields["NS.time"] as? NSNumber {
                let date = Date(timeIntervalSinceReferenceDate: seconds.doubleValue)
                return .object(type: "NSDate", fields: [
                    TraceField(name: "value", value: .string(ISO8601DateFormatter().string(from: date)))
                ])
            }
        case "NSURL":
            let relative = fields["NS.relative"].map { resolve($0, depth: depth + 1) } ?? .null
            let base = fields["NS.base"].map { resolve($0, depth: depth + 1) } ?? .null
            return .object(type: "NSURL", fields: [
                TraceField(name: "relative", value: relative),
                TraceField(name: "base", value: base),
            ])
        default:
            break
        }

        let decoded = fields.keys.filter { $0 != "$class" }.sorted().map {
            TraceField(name: $0, value: resolve(fields[$0] as Any, depth: depth + 1))
        }
        return .object(type: className ?? "Archived object #\(index)", fields: decoded)
    }

    private mutating func convert(_ value: Any, depth: Int) -> TraceValue {
        if let string = value as? String { return .string(string) }
        if let data = value as? Data { return .data(data, interpretation: nil) }
        if let date = value as? Date { return .string(ISO8601DateFormatter().string(from: date)) }
        if let number = value as? NSNumber {
            return KeyedArchiveDecoder.numberValue(number)
        }
        if let array = value as? [Any] {
            return .array(array.map { resolve($0, depth: depth + 1) })
        }
        if let fields = archiveDictionary(value) {
            return .dictionary(fields.keys.sorted().map {
                TraceField(name: $0, value: resolve(fields[$0] as Any, depth: depth + 1))
            })
        }
        return .string(String(describing: value))
    }

    private mutating func className(for reference: Any?) -> String? {
        guard let reference, let index = KeyedArchiveDecoder.uidValue(reference),
              objects.indices.contains(index), let fields = archiveDictionary(objects[index]) else {
            return nil
        }
        return fields["$classname"] as? String
    }

    private func archiveDictionary(_ value: Any) -> [String: Any]? {
        if let fields = value as? [String: Any] { return fields }
        guard let fields = value as? [AnyHashable: Any] else { return nil }
        return Dictionary(uniqueKeysWithValues: fields.map { (String(describing: $0.key), $0.value) })
    }
}

public enum EmbeddedPayloadDecoder {
    public static func decode(_ data: Data, format: UInt8) -> TraceValue {
        do {
            let decoded = format == 1
                ? try XPCSerializationDecoder.decode(data)
                : .data(data, interpretation: nil)
            return expandEmbeddedData(decoded)
        } catch {
            return .error(error.localizedDescription)
        }
    }

    public static func expandEmbeddedData(_ value: TraceValue) -> TraceValue {
        expandEmbeddedData(value, sourceOffset: nil)
    }

    private static func expandEmbeddedData(
        _ value: TraceValue,
        sourceOffset: Int?
    ) -> TraceValue {
        switch value {
        case .data(let data, let existingInterpretation):
            let interpretation = existingInterpretation
                ?? interpretData(data, sourceOffset: sourceOffset.map { $0 + 8 })
            return .data(
                data,
                interpretation: interpretation.map { expandEmbeddedData($0, sourceOffset: sourceOffset) }
            )
        case .array(let values):
            return .array(values.map { expandEmbeddedData($0, sourceOffset: sourceOffset) })
        case .dictionary(let fields):
            return .dictionary(fields.map {
                TraceField(
                    name: $0.name,
                    value: expandEmbeddedData($0.value, sourceOffset: sourceOffset),
                    id: $0.id
                )
            })
        case .object(let type, let fields):
            return .object(type: type, fields: fields.map {
                TraceField(
                    name: $0.name,
                    value: expandEmbeddedData($0.value, sourceOffset: sourceOffset),
                    id: $0.id
                )
            })
        case .sourced(let range, let nested):
            return .sourced(
                range: range,
                value: expandEmbeddedData(nested, sourceOffset: range.lowerBound)
            )
        default:
            return value
        }
    }

    private static func interpretData(_ data: Data, sourceOffset: Int?) -> TraceValue? {
        guard !data.isEmpty else { return nil }
        let offset = sourceOffset ?? 0

        if data.starts(with: Data("bplist".utf8)) {
            if data.starts(with: Data("bplist17".utf8)) {
                let label = String(format: "Binary property list v17 at 0x%X", offset)
                do {
                    let decoded = try BPlist17Decoder.decode(data, sourceOffset: offset)
                    return .object(type: label, fields: [
                        TraceField(name: "Decoded value", value: decoded)
                    ])
                } catch {
                    return .object(type: label, fields: [
                        TraceField(name: "Decode error", value: .error(error.localizedDescription))
                    ])
                }
            }

            let label = String(format: "Binary property list v0 at 0x%X", offset)
            if let archive = KeyedArchiveDecoder.decodeIfPresent(data) {
                return .object(type: label, fields: [
                    TraceField(name: "NSKeyedArchiver", value: archive)
                ])
            }
            var format = PropertyListSerialization.PropertyListFormat.binary
            if let plist = try? PropertyListSerialization.propertyList(
                from: data,
                options: [],
                format: &format
            ) {
                return .object(
                    type: label,
                    fields: fields(for: KeyedArchiveDecoder.propertyListValue(plist))
                )
            }
            return nil
        }

        let firstContentByte = data.first { ![0x09, 0x0A, 0x0D, 0x20].contains($0) }
        if firstContentByte == UInt8(ascii: "{") || firstContentByte == UInt8(ascii: "[") {
            if let json = try? JSONSerialization.jsonObject(with: data) {
                return .object(
                    type: String(format: "JSON at 0x%X", offset),
                    fields: fields(for: KeyedArchiveDecoder.propertyListValue(json))
                )
            }
        }

        if firstContentByte == UInt8(ascii: "<") {
            var format = PropertyListSerialization.PropertyListFormat.xml
            if let plist = try? PropertyListSerialization.propertyList(
                from: data,
                options: [],
                format: &format
            ) {
                return .object(
                    type: String(format: "XML property list at 0x%X", offset),
                    fields: fields(for: KeyedArchiveDecoder.propertyListValue(plist))
                )
            }
        }
        return nil
    }

    private static func fields(for value: TraceValue) -> [TraceField] {
        switch value {
        case .dictionary(let fields), .object(_, let fields): fields
        default: [TraceField(name: "Value", value: value)]
        }
    }
}
