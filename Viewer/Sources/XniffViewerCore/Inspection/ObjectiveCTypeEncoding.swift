import Foundation

public enum ObjectiveCTypeKind: Sendable, Equatable {
    case void
    case signedInteger
    case unsignedInteger
    case floatingPoint
    case bool
    case object(className: String?, protocols: [String])
    case block
    case classObject
    case selector
    case cString
    case pointer
    case array
    case structure(name: String?)
    case union(name: String?)
    case bitField
    case vector
    case unknown
}

public struct ObjectiveCTypeDescriptor: Sendable, Equatable {
    public let encoding: String
    public let kind: ObjectiveCTypeKind
    public let displayName: String
    public let qualifiers: [String]

    public var objectClassName: String? {
        guard case .object(let className, _) = kind else { return nil }
        return className
    }

    public var isBlock: Bool { kind == .block }
}

public struct ObjectiveCMethodArgument: Sendable, Equatable {
    public let type: ObjectiveCTypeDescriptor
    public let offset: Int?
}

public struct ObjectiveCMethodSignature: Sendable, Equatable {
    public let encoding: String
    public let returnType: ObjectiveCTypeDescriptor
    public let frameLength: Int?
    public let arguments: [ObjectiveCMethodArgument]

    public static func parse(_ encoding: String) -> ObjectiveCMethodSignature? {
        var parser = ObjectiveCTypeParser(encoding)
        guard let returnType = parser.readType() else { return nil }
        let frameLength = parser.readNumber()
        var arguments: [ObjectiveCMethodArgument] = []
        while !parser.isAtEnd {
            guard let type = parser.readType() else { return nil }
            arguments.append(ObjectiveCMethodArgument(type: type, offset: parser.readNumber()))
        }
        return ObjectiveCMethodSignature(
            encoding: encoding,
            returnType: returnType,
            frameLength: frameLength,
            arguments: arguments
        )
    }

    public func wireArguments(for kind: FoundationXPCInvocationKind) -> [ObjectiveCMethodArgument] {
        let implicitCount = kind == .request ? 2 : 1
        return Array(arguments.dropFirst(min(implicitCount, arguments.count)))
    }
}

private struct ObjectiveCTypeParser {
    private struct AggregateBody {
        let name: String?
    }

    private let bytes: [UInt8]
    private var offset = 0

    init(_ encoding: String) {
        bytes = Array(encoding.utf8)
    }

    var isAtEnd: Bool { offset == bytes.count }

    mutating func readNumber() -> Int? {
        let start = offset
        if byte(at: offset) == UInt8(ascii: "+") || byte(at: offset) == UInt8(ascii: "-") {
            offset += 1
        }
        let digitsStart = offset
        while let value = byte(at: offset), value.isASCIIDigit {
            offset += 1
        }
        guard offset > digitsStart else {
            offset = start
            return nil
        }
        return Int(String(decoding: bytes[start..<offset], as: UTF8.self))
    }

    mutating func readType() -> ObjectiveCTypeDescriptor? {
        let start = offset
        var qualifiers: [String] = []
        while let value = byte(at: offset), let qualifier = qualifierName(value) {
            qualifiers.append(qualifier)
            offset += 1
        }
        guard let marker = byte(at: offset) else { return nil }
        offset += 1

        let kind: ObjectiveCTypeKind
        var displayName: String
        switch marker {
        case UInt8(ascii: "v"):
            kind = .void
            displayName = "void"
        case UInt8(ascii: "c"):
            kind = .signedInteger
            displayName = "char"
        case UInt8(ascii: "C"):
            kind = .unsignedInteger
            displayName = "unsigned char"
        case UInt8(ascii: "s"):
            kind = .signedInteger
            displayName = "short"
        case UInt8(ascii: "S"):
            kind = .unsignedInteger
            displayName = "unsigned short"
        case UInt8(ascii: "i"):
            kind = .signedInteger
            displayName = "int"
        case UInt8(ascii: "I"):
            kind = .unsignedInteger
            displayName = "unsigned int"
        case UInt8(ascii: "l"):
            kind = .signedInteger
            displayName = "long"
        case UInt8(ascii: "L"):
            kind = .unsignedInteger
            displayName = "unsigned long"
        case UInt8(ascii: "q"):
            kind = .signedInteger
            displayName = "long long"
        case UInt8(ascii: "Q"):
            kind = .unsignedInteger
            displayName = "unsigned long long"
        case UInt8(ascii: "f"):
            kind = .floatingPoint
            displayName = "float"
        case UInt8(ascii: "d"):
            kind = .floatingPoint
            displayName = "double"
        case UInt8(ascii: "D"):
            kind = .floatingPoint
            displayName = "long double"
        case UInt8(ascii: "B"):
            kind = .bool
            displayName = "BOOL"
        case UInt8(ascii: "@"):
            if byte(at: offset) == UInt8(ascii: "?") {
                offset += 1
                kind = .block
                displayName = "block"
            } else if byte(at: offset) == UInt8(ascii: "\"") {
                guard let annotation = readQuotedString() else { return nil }
                let parsed = parseObjectAnnotation(annotation)
                kind = .object(className: parsed.className, protocols: parsed.protocols)
                displayName = parsed.displayName
            } else {
                kind = .object(className: nil, protocols: [])
                displayName = "object"
            }
        case UInt8(ascii: "#"):
            kind = .classObject
            displayName = "Class"
        case UInt8(ascii: ":"):
            kind = .selector
            displayName = "SEL"
        case UInt8(ascii: "*"):
            kind = .cString
            displayName = "char *"
        case UInt8(ascii: "^"):
            guard let pointee = readType() else { return nil }
            kind = .pointer
            displayName = "\(pointee.displayName) *"
        case UInt8(ascii: "["):
            let count = readNumber()
            guard let element = readType(), consume(UInt8(ascii: "]")) else { return nil }
            kind = .array
            displayName = count.map { "\(element.displayName)[\($0)]" } ?? "\(element.displayName)[]"
        case UInt8(ascii: "{"):
            guard let aggregate = readAggregateBody(closing: UInt8(ascii: "}")) else { return nil }
            kind = .structure(name: aggregate.name)
            displayName = aggregate.name.map { "struct \($0)" } ?? "struct"
        case UInt8(ascii: "("):
            guard let aggregate = readAggregateBody(closing: UInt8(ascii: ")")) else { return nil }
            kind = .union(name: aggregate.name)
            displayName = aggregate.name.map { "union \($0)" } ?? "union"
        case UInt8(ascii: "b"):
            let width = readNumber()
            kind = .bitField
            displayName = width.map { "bit field (\($0) bits)" } ?? "bit field"
        case UInt8(ascii: "!"):
            guard byte(at: offset) == UInt8(ascii: "[") else { return nil }
            offset += 1
            guard readAggregateBody(closing: UInt8(ascii: "]")) != nil else { return nil }
            kind = .vector
            displayName = "vector"
        case UInt8(ascii: "?"):
            kind = .unknown
            displayName = "unknown"
        default:
            return nil
        }

        if !qualifiers.isEmpty {
            displayName = (qualifiers + [displayName]).joined(separator: " ")
        }
        return ObjectiveCTypeDescriptor(
            encoding: String(decoding: bytes[start..<offset], as: UTF8.self),
            kind: kind,
            displayName: displayName,
            qualifiers: qualifiers
        )
    }

    private func byte(at index: Int) -> UInt8? {
        bytes.indices.contains(index) ? bytes[index] : nil
    }

    private mutating func consume(_ expected: UInt8) -> Bool {
        guard byte(at: offset) == expected else { return false }
        offset += 1
        return true
    }

    private mutating func readQuotedString() -> String? {
        guard consume(UInt8(ascii: "\"")) else { return nil }
        var result: [UInt8] = []
        while let value = byte(at: offset) {
            offset += 1
            if value == UInt8(ascii: "\"") {
                return String(decoding: result, as: UTF8.self)
            }
            if value == UInt8(ascii: "\\"), let escaped = byte(at: offset) {
                offset += 1
                result.append(escaped)
            } else {
                result.append(value)
            }
        }
        return nil
    }

    private mutating func readAggregateBody(closing: UInt8) -> AggregateBody? {
        let nameStart = offset
        while let value = byte(at: offset), value != UInt8(ascii: "="), value != closing {
            offset += 1
        }
        guard let delimiter = byte(at: offset) else { return nil }
        let rawName = String(decoding: bytes[nameStart..<offset], as: UTF8.self)
        let name = rawName == "?" || rawName.isEmpty ? nil : rawName
        if delimiter == closing {
            offset += 1
            return AggregateBody(name: name)
        }
        offset += 1
        while byte(at: offset) != closing {
            if byte(at: offset) == UInt8(ascii: "\"") {
                guard readQuotedString() != nil else { return nil }
                continue
            }
            guard readType() != nil else { return nil }
        }
        offset += 1
        return AggregateBody(name: name)
    }

    private func qualifierName(_ marker: UInt8) -> String? {
        switch marker {
        case UInt8(ascii: "r"): "const"
        case UInt8(ascii: "n"): "in"
        case UInt8(ascii: "N"): "inout"
        case UInt8(ascii: "o"): "out"
        case UInt8(ascii: "O"): "bycopy"
        case UInt8(ascii: "R"): "byref"
        case UInt8(ascii: "V"): "oneway"
        case UInt8(ascii: "A"): "atomic"
        case UInt8(ascii: "j"): "complex"
        default: nil
        }
    }

    private func parseObjectAnnotation(
        _ annotation: String
    ) -> (className: String?, protocols: [String], displayName: String) {
        let bytes = Array(annotation.utf8)
        let firstProtocol = bytes.firstIndex(of: UInt8(ascii: "<")) ?? bytes.endIndex
        let classBytes = bytes[..<firstProtocol]
        let className = classBytes.isEmpty ? nil : String(decoding: classBytes, as: UTF8.self)
        var protocols: [String] = []
        var index = firstProtocol
        while index < bytes.count {
            guard bytes[index] == UInt8(ascii: "<"),
                  let end = bytes[(index + 1)...].firstIndex(of: UInt8(ascii: ">")) else {
                break
            }
            protocols.append(String(decoding: bytes[(index + 1)..<end], as: UTF8.self))
            index = end + 1
        }
        let protocolText = protocols.map { "<\($0)>" }.joined()
        let displayName = className.map { "\($0)\(protocolText) *" }
            ?? (protocolText.isEmpty ? "object" : "id\(protocolText)")
        return (className, protocols, displayName)
    }
}

private extension UInt8 {
    var isASCIIDigit: Bool { self >= UInt8(ascii: "0") && self <= UInt8(ascii: "9") }
}
