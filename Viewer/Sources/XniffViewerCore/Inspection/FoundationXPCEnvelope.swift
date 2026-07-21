import Foundation

public struct FoundationXPCInvocation: Sendable {
    public let operation: String?
    public let signature: String
    public let arguments: TraceValue

    init?(decodedRoot: TraceValue) {
        guard case .array(let fields) = decodedRoot.foundationUnwrapped,
              fields.count >= 3,
              let signature = fields[1].foundationString else {
            return nil
        }
        self.operation = fields[0].foundationString
        self.signature = signature
        self.arguments = fields[2]
    }
}

public struct FoundationXPCEnvelope: Sendable {
    public let decodedRoot: TraceValue
    public let invocation: FoundationXPCInvocation?
    public let metadata: [TraceField]
    public let flags: UInt64?
    public let proxyNumber: UInt64?
    public let sequence: UInt64?
    public let replySignature: String?

    public var logicalBody: TraceValue { invocation?.arguments ?? decodedRoot }
    public var operation: String? { invocation?.operation }
    public var invocationSignature: String? { invocation?.signature }
    public var replyObjectTypes: [String] {
        replySignature.map { ObjectiveCTypeEncoding.objectTypes(in: $0) } ?? []
    }

    public init(
        decodedRoot: TraceValue,
        metadata: [TraceField],
        flags: UInt64?,
        proxyNumber: UInt64?,
        sequence: UInt64?,
        replySignature: String?
    ) {
        self.decodedRoot = decodedRoot
        self.invocation = FoundationXPCInvocation(decodedRoot: decodedRoot)
        self.metadata = metadata
        self.flags = flags
        self.proxyNumber = proxyNumber
        self.sequence = sequence
        self.replySignature = replySignature
    }
}

public enum FoundationXPCEnvelopeDecoder {
    private enum Key {
        static let flags = "f"
        static let proxyNumber = "proxynum"
        static let replySignature = "replysig"
        static let root = "root"
        static let sequence = "sequence"
    }

    public static func decode(_ value: TraceValue) -> FoundationXPCEnvelope? {
        guard case .dictionary(let fields) = value.foundationUnwrapped,
              let root = fields.foundationValue(named: Key.root),
              let decodedRoot = decodedArchive(in: root) else {
            return nil
        }

        return FoundationXPCEnvelope(
            decodedRoot: decodedRoot,
            metadata: fields.filter { $0.name != Key.root },
            flags: fields.foundationValue(named: Key.flags)?.foundationUnsigned,
            proxyNumber: fields.foundationValue(named: Key.proxyNumber)?.foundationUnsigned,
            sequence: fields.foundationValue(named: Key.sequence)?.foundationUnsigned,
            replySignature: fields.foundationValue(named: Key.replySignature)?.foundationString
        )
    }

    private static func decodedArchive(in value: TraceValue) -> TraceValue? {
        guard case .data(_, let interpretation) = value.foundationUnwrapped,
              let interpretation,
              case .object(let type, let fields) = interpretation.foundationUnwrapped,
              type.hasPrefix("Binary property list") else {
            return nil
        }

        let decodedFieldNames = ["Decoded value", "NSKeyedArchiver", "Value"]
        return decodedFieldNames.lazy.compactMap { name in
            fields.foundationValue(named: name)
        }.first
    }
}

private enum ObjectiveCTypeEncoding {
    static func objectTypes(in signature: String) -> [String] {
        let pattern = #"@\"([^\"]+)\""#
        guard let expression = try? NSRegularExpression(pattern: pattern) else { return [] }
        let range = NSRange(signature.startIndex..<signature.endIndex, in: signature)
        return expression.matches(in: signature, range: range).compactMap { match in
            guard match.numberOfRanges > 1,
                  let typeRange = Range(match.range(at: 1), in: signature) else { return nil }
            return String(signature[typeRange])
        }
    }
}

private extension TraceValue {
    var foundationUnwrapped: TraceValue {
        if case .sourced(_, let nested) = self { return nested.foundationUnwrapped }
        return self
    }

    var foundationString: String? {
        if case .string(let value) = foundationUnwrapped { return value }
        return nil
    }

    var foundationUnsigned: UInt64? {
        switch foundationUnwrapped {
        case .unsigned(let value): value
        case .signed(let value) where value >= 0: UInt64(value)
        default: nil
        }
    }
}

private extension [TraceField] {
    func foundationValue(named name: String) -> TraceValue? {
        first(where: { $0.name == name })?.value
    }
}
