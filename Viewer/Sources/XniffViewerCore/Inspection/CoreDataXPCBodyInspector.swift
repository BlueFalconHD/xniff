import Foundation

public struct CoreDataXPCMessage: Sendable {
    public let logicalBody: TraceValue
    public let code: Int64?
    public let pinningMode: String?
    public let token: String?
    public let processName: String?
    public let metadata: [TraceField]

    public var protocolName: String { "Core Data XPC" }

    public var operationName: String {
        switch code {
        case 0: "Reply"
        case 2: "Fetch request"
        case .some(let code): "Operation \(code)"
        case nil: "Message"
        }
    }
}

public enum CoreDataXPCMessageDecoder {
    public static func decode(_ value: TraceValue) -> CoreDataXPCMessage? {
        guard let message = findMessage(in: value, depth: 0),
              case .object(_, let fields) = message.unwrapped,
              let bodyField = fields.first(where: { $0.name == "NSCoreDataXPCMessageBody" }) else {
            return nil
        }

        let code = fields.first(named: "NSCoreDataXPCMessageCode")?.signedNumber
        let outerBody = decodedData(bodyField.value) ?? bodyField.value
        let outerValue = unwrappedRepresentation(outerBody)
        let payload: TraceValue
        let pinningMode: String?
        if case .array(let values) = outerValue.unwrapped,
           values.count == 2,
           let first = values.first,
           let pinning = values.last?.plainString {
            payload = first
            pinningMode = pinning
        } else {
            payload = outerValue
            pinningMode = nil
        }

        let archive = decodedData(payload) ?? payload
        let decodedBody = unwrappedRepresentation(archive)
        return CoreDataXPCMessage(
            logicalBody: semanticBody(decodedBody, code: code),
            code: code,
            pinningMode: pinningMode,
            token: fields.first(named: "NSCoreDataXPCMessageToken")?.plainString,
            processName: fields.first(named: "NSCoreDataXPCMessageProcessName")?.plainString,
            metadata: fields.filter { $0.name != "NSCoreDataXPCMessageBody" }
        )
    }

    private static func semanticBody(_ value: TraceValue, code: Int64?) -> TraceValue {
        if code == 0,
           case .array(let values) = value.unwrapped,
           let declaredCount = values.first?.nonnegativeInteger,
           declaredCount == values.count - 1 {
            // TODO: Reverse the per-operation Core Data result row schemas and
            // replace positional row arrays with stable, named fields.
            return value.replacingOutermostValue(with: .object(
                type: "Core Data result set",
                fields: [
                    TraceField(name: "Results", value: .array(Array(values.dropFirst()))),
                ]
            ))
        }

        if code == 2,
           case .array(let slots) = value.unwrapped,
           slots.count == 11 {
            var fields: [TraceField] = []
            fields.append(TraceField(name: "Entity", value: slots[0]))
            if !slots[1].isProtocolDefault {
                fields.append(TraceField(name: "Request options", value: slots[1]))
            }
            if !slots[2].isProtocolDefault {
                fields.append(TraceField(name: "Sort descriptors", value: slots[2]))
            }
            if !slots[3].isProtocolDefault {
                fields.append(TraceField(name: "Predicate", value: slots[3]))
            }
            for index in 4..<slots.count where !slots[index].isProtocolDefault {
                fields.append(TraceField(name: "Unidentified field \(index)", value: slots[index]))
            }
            return value.replacingOutermostValue(with: .object(
                type: "Core Data fetch request",
                fields: fields
            ))
        }

        if code == 0,
           case .data(_, let interpretation) = value.unwrapped,
           interpretation == nil {
            return value.replacingOutermostValue(with: .object(
                type: "Opaque Core Data result buffer",
                fields: [TraceField(name: "Undecoded result data", value: value.unwrapped)]
            ))
        }

        return value
    }

    private static func findMessage(in value: TraceValue, depth: Int) -> TraceValue? {
        guard depth < 8 else { return nil }
        switch value.unwrapped {
        case .object(let type, _) where type == "NSCoreDataXPCMessage":
            return value
        case .array(let values):
            return values.lazy.compactMap { findMessage(in: $0, depth: depth + 1) }.first
        case .dictionary(let fields), .object(_, let fields):
            return fields.lazy.compactMap { findMessage(in: $0.value, depth: depth + 1) }.first
        default:
            return nil
        }
    }

    private static func decodedData(_ value: TraceValue) -> TraceValue? {
        guard case .data(_, let interpretation) = value.unwrapped, let interpretation else { return nil }
        return value.replacingOutermostValue(with: interpretation)
    }

    private static func unwrappedRepresentation(_ value: TraceValue) -> TraceValue {
        var current = value
        for _ in 0..<8 {
            guard case .object(let type, let fields) = current.unwrapped,
                  type.hasPrefix("Binary property list") || type.hasPrefix("JSON at "),
                  fields.count == 1 else {
                break
            }
            current = current.replacingOutermostValue(with: fields[0].value)
        }
        return current
    }
}

public struct CoreDataXPCBodyInspector: TraceBodyInspector {
    public let identifier = StandardBodyInspectorID.coreDataXPC
    public let parentIdentifier: String? = StandardBodyInspectorID.foundationNSXPC
    public let priority = 200

    public init() {}

    public func inspect(_ context: BodyInspectorContext) -> BodyInspection? {
        guard let parent = context.inspection(parentIdentifier!),
              let message = CoreDataXPCMessageDecoder.decode(parent.body) else {
            return nil
        }

        var summary = [message.operationName]
        if let code = message.code { summary.append("code \(code)") }
        if let pinningMode = message.pinningMode { summary.append(pinningMode) }

        return BodyInspection(
            id: identifier,
            name: "Core Data",
            priority: priority,
            parentID: parentIdentifier,
            body: message.logicalBody,
            title: message.protocolName,
            summary: summary.joined(separator: " · "),
            systemImage: "cylinder.split.1x2",
            metadata: message.metadata
        )
    }
}

private extension TraceValue {
    var unwrapped: TraceValue {
        if case .sourced(_, let nested) = self { return nested.unwrapped }
        return self
    }

    var plainString: String? {
        if case .string(let value) = unwrapped { return value }
        return nil
    }

    var signedNumber: Int64? {
        switch unwrapped {
        case .signed(let value): value
        case .unsigned(let value) where value <= UInt64(Int64.max): Int64(value)
        case .double(let value) where value.rounded() == value: Int64(exactly: value)
        default: nil
        }
    }

    var nonnegativeInteger: Int? {
        switch unwrapped {
        case .signed(let value) where value >= 0 && value <= Int64(Int.max): Int(value)
        case .unsigned(let value) where value <= UInt64(Int.max): Int(value)
        default: nil
        }
    }

    var isProtocolDefault: Bool {
        switch unwrapped {
        case .null: true
        case .signed(0), .unsigned(0), .double(0): true
        case .array(let values): values.isEmpty
        case .dictionary(let fields): fields.isEmpty
        case .object(let type, _): type == "NSNull"
        default: false
        }
    }

    func replacingOutermostValue(with replacement: TraceValue) -> TraceValue {
        if case .sourced(let range, _) = self {
            return .sourced(range: range, value: replacement)
        }
        return replacement
    }
}

private extension [TraceField] {
    func first(named name: String) -> TraceValue? {
        first(where: { $0.name == name })?.value
    }
}
