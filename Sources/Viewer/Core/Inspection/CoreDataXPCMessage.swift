import Foundation

public struct CoreDataXPCMessage: Sendable {
    public let operation: CoreDataOperation
    public let token: String?
    public let contextName: String?
    public let transactionAuthor: String?
    public let processName: String?
    public let allowsAncillaryEntities: Bool
    public let metadata: [TraceField]

    public var logicalBody: TraceValue { operation.body }
    public var code: Int64? { operation.code }
    public var operationName: String { operation.name }
}

public enum CoreDataXPCMessageDecoder {
    private enum Key {
        static let body = "NSCoreDataXPCMessageBody"
        static let code = "NSCoreDataXPCMessageCode"
        static let token = "NSCoreDataXPCMessageToken"
        static let contextName = "NSCoreDataXPCMessageContextName"
        static let transactionAuthor = "NSCoreDataXPCMessageContextTransactionAuthor"
        static let processName = "NSCoreDataXPCMessageProcessName"
        static let allowsAncillary = "NSCoreDataXPCMessageContextAllowAncillary"
    }

    public static func decode(
        _ value: TraceValue,
        operations: CoreDataOperationRegistry = .standard,
        request: CoreDataXPCMessage? = nil
    ) -> CoreDataXPCMessage? {
        guard let message = findMessage(in: value),
              case .object(_, let fields) = message.coreDataUnwrapped else {
            return nil
        }

        let code = fields.coreDataValue(named: Key.code)?.coreDataSignedNumber
        let body = fields.coreDataValue(named: Key.body).map(CoreDataArchiveRepresentation.decode)
        let operation: CoreDataOperation
        if code == 2, body == nil, let error = replyError(in: value) {
            operation = CoreDataOperation(
                code: code,
                name: "Error response",
                body: CoreDataArchiveRepresentation.decode(error)
            )
        } else {
            operation = operations.decode(body, code: code, request: request)
        }

        return CoreDataXPCMessage(
            operation: operation,
            token: fields.coreDataValue(named: Key.token)?.coreDataString,
            contextName: fields.coreDataValue(named: Key.contextName)?.coreDataString,
            transactionAuthor: fields.coreDataValue(named: Key.transactionAuthor)?.coreDataString,
            processName: fields.coreDataValue(named: Key.processName)?.coreDataString,
            allowsAncillaryEntities: fields.coreDataValue(named: Key.allowsAncillary)?.coreDataBool ?? false,
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

    private static func replyError(in value: TraceValue) -> TraceValue? {
        guard let arguments = replyArguments(in: value),
              let messageIndex = arguments.firstIndex(where: { findMessage(in: $0) != nil }) else {
            return nil
        }

        return arguments.dropFirst(messageIndex + 1).first(where: { argument in
            if case .null = argument.coreDataUnwrapped { return false }
            return true
        })
    }

    private static func replyArguments(in value: TraceValue) -> [TraceValue]? {
        switch value.coreDataUnwrapped {
        case .object("NSXPC reply", let fields):
            guard case .array(let arguments) = fields.coreDataValue(named: "Arguments")?.coreDataUnwrapped else {
                return nil
            }
            return arguments.compactMap { argument in
                guard case .object(_, let fields) = argument.coreDataUnwrapped else { return nil }
                return fields.coreDataValue(named: "Value")
            }
        case .array(let values):
            // Foundation's decoded invocation root is [null, signature, arguments].
            if values.count >= 3,
               case .null = values[0].coreDataUnwrapped,
               case .array(let arguments) = values[2].coreDataUnwrapped {
                return arguments
            }
            return values
        case .dictionary(let fields), .object(_, let fields):
            return fields.lazy.compactMap { replyArguments(in: $0.value) }.first
        default:
            return nil
        }
    }
}

enum CoreDataArchiveRepresentation {
    static func decode(_ value: TraceValue) -> TraceValue {
        guard case .data(_, let interpretation) = value.coreDataUnwrapped,
              let interpretation else {
            return value
        }
        return value.replacingOutermostSourcedValue(with: unwrap(interpretation))
    }

    static func unwrap(_ value: TraceValue) -> TraceValue {
        var current = value
        for _ in 0..<32 {
            guard case .object(let type, let fields) = current.coreDataUnwrapped,
                  isRepresentationWrapper(type), fields.count == 1 else {
                return current
            }
            current = current.replacingOutermostSourcedValue(with: fields[0].value)
        }
        return current
    }

    private static func isRepresentationWrapper(_ type: String) -> Bool {
        type.hasPrefix("Binary property list")
            || type.hasPrefix("JSON at ")
            || type.hasPrefix("XML property list")
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

    var coreDataBool: Bool? {
        switch coreDataUnwrapped {
        case .bool(let value): value
        case .signed(let value): value != 0
        case .unsigned(let value): value != 0
        default: nil
        }
    }

    var coreDataSignedNumber: Int64? {
        switch coreDataUnwrapped {
        case .signed(let value): value
        case .unsigned(let value) where value <= UInt64(Int64.max): Int64(value)
        case .double(let value) where value.rounded() == value: Int64(exactly: value)
        default: nil
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
