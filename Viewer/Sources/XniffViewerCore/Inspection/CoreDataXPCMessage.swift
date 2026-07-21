import Foundation

public struct CoreDataXPCMessage: Sendable {
    public let operation: CoreDataOperation
    public let pinningMode: String?
    public let token: String?
    public let processName: String?
    public let metadata: [TraceField]

    public var logicalBody: TraceValue { operation.body }
    public var code: Int64? { operation.code }
    public var operationName: String { operation.name }
}

public enum CoreDataXPCMessageDecoder {
    private enum Key {
        static let body = "NSCoreDataXPCMessageBody"
        static let code = "NSCoreDataXPCMessageCode"
        static let processName = "NSCoreDataXPCMessageProcessName"
        static let token = "NSCoreDataXPCMessageToken"
    }

    public static func decode(
        _ value: TraceValue,
        operations: CoreDataOperationRegistry = .standard
    ) -> CoreDataXPCMessage? {
        guard let message = findMessage(in: value),
              case .object(_, let fields) = message.coreDataUnwrapped,
              let encodedBody = fields.coreDataValue(named: Key.body) else {
            return nil
        }

        let code = fields.coreDataValue(named: Key.code)?.coreDataSignedNumber
        let (payload, pinningMode) = extractPayload(from: decodedData(encodedBody) ?? encodedBody)
        let archive = decodedData(payload) ?? payload
        let decodedBody = unwrapRepresentation(archive)

        return CoreDataXPCMessage(
            operation: operations.decode(decodedBody, code: code),
            pinningMode: pinningMode,
            token: fields.coreDataValue(named: Key.token)?.coreDataString,
            processName: fields.coreDataValue(named: Key.processName)?.coreDataString,
            metadata: fields.filter { $0.name != Key.body }
        )
    }

    private static func findMessage(in value: TraceValue) -> TraceValue? {
        switch value.coreDataUnwrapped {
        case .object(let type, _) where type == "NSCoreDataXPCMessage":
            return value
        case .array(let values):
            return values.lazy.compactMap(findMessage).first
        case .dictionary(let fields), .object(_, let fields):
            return fields.lazy.compactMap { findMessage(in: $0.value) }.first
        default:
            return nil
        }
    }

    private static func extractPayload(from value: TraceValue) -> (TraceValue, String?) {
        guard case .array(let values) = value.coreDataUnwrapped,
              values.count == 2,
              let payload = values.first,
              let pinningMode = values.last?.coreDataString else {
            return (value, nil)
        }
        return (payload, pinningMode)
    }

    private static func decodedData(_ value: TraceValue) -> TraceValue? {
        guard case .data(_, let interpretation) = value.coreDataUnwrapped,
              let interpretation else { return nil }
        return value.replacingOutermostSourcedValue(with: interpretation)
    }

    private static func unwrapRepresentation(_ value: TraceValue) -> TraceValue {
        var current = value
        for _ in 0..<32 {
            guard case .object(let type, let fields) = current.coreDataUnwrapped,
                  type.hasPrefix("Binary property list") || type.hasPrefix("JSON at "),
                  fields.count == 1 else {
                return current
            }
            current = current.replacingOutermostSourcedValue(with: fields[0].value)
        }
        return current
    }
}

extension TraceValue {
    var coreDataUnwrapped: TraceValue {
        if case .sourced(_, let nested) = self { return nested.coreDataUnwrapped }
        return self
    }

    var coreDataString: String? {
        if case .string(let value) = coreDataUnwrapped { return value }
        return nil
    }

    var coreDataSignedNumber: Int64? {
        switch coreDataUnwrapped {
        case .signed(let value): value
        case .unsigned(let value) where value <= UInt64(Int64.max): Int64(value)
        case .double(let value) where value.rounded() == value: Int64(exactly: value)
        default: nil
        }
    }

    var isCoreDataProtocolDefault: Bool {
        switch coreDataUnwrapped {
        case .null: true
        case .signed(0), .unsigned(0), .double(0): true
        case .array(let values): values.isEmpty
        case .dictionary(let fields): fields.isEmpty
        case .object(let type, _): type == "NSNull"
        default: false
        }
    }

    func replacingOutermostSourcedValue(with replacement: TraceValue) -> TraceValue {
        if case .sourced(let range, _) = self {
            return .sourced(range: range, value: replacement)
        }
        return replacement
    }
}

extension [TraceField] {
    func coreDataValue(named name: String) -> TraceValue? {
        first(where: { $0.name == name })?.value
    }
}
