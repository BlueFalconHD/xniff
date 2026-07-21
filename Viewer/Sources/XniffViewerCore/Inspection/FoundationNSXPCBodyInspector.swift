import Foundation

public struct FoundationXPCEnvelope: Sendable {
    public let logicalBody: TraceValue
    public let metadata: [TraceField]
    public let operation: String?
    public let invocationSignature: String?
    public let flags: UInt64?
    public let proxyNumber: UInt64?
    public let sequence: UInt64?
    public let replySignature: String?
    public let replyObjectTypes: [String]

    public var protocolName: String { "Foundation NSXPCConnection" }

    public init(
        decodedRoot: TraceValue,
        metadata: [TraceField],
        flags: UInt64?,
        proxyNumber: UInt64?,
        sequence: UInt64?,
        replySignature: String?
    ) {
        let invocation = Self.invocation(in: decodedRoot)
        self.logicalBody = invocation?.arguments ?? decodedRoot
        self.metadata = metadata
        self.operation = invocation?.operation
        self.invocationSignature = invocation?.signature
        self.flags = flags
        self.proxyNumber = proxyNumber
        self.sequence = sequence
        self.replySignature = replySignature
        self.replyObjectTypes = replySignature.map(Self.objectTypes) ?? []
    }

    private static func invocation(
        in value: TraceValue
    ) -> (operation: String?, signature: String, arguments: TraceValue)? {
        guard case .array(let fields) = value.unwrapped,
              fields.count >= 3,
              let signature = fields[1].plainString else {
            return nil
        }
        return (fields[0].plainString, signature, fields[2])
    }

    private static func objectTypes(in signature: String) -> [String] {
        // `replysig` is the Objective-C reply block ABI. It can describe reply
        // object types, but it is not a class schema for the invocation body.
        // Concrete class names and keyed properties come from the archived
        // values themselves.
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

public enum FoundationXPCEnvelopeDecoder {
    public static func decode(_ value: TraceValue) -> FoundationXPCEnvelope? {
        guard case .dictionary(let fields) = value.unwrapped,
              let root = fields.first(where: { $0.name == "root" }),
              let logicalBody = decodedBPlist17(in: root.value) else {
            return nil
        }

        return FoundationXPCEnvelope(
            decodedRoot: logicalBody,
            metadata: fields.filter { $0.name != "root" },
            flags: fields.unsignedValue(named: "f"),
            proxyNumber: fields.unsignedValue(named: "proxynum"),
            sequence: fields.unsignedValue(named: "sequence"),
            replySignature: fields.stringValue(named: "replysig")
        )
    }

    private static func decodedBPlist17(in value: TraceValue) -> TraceValue? {
        guard case .data(_, let interpretation) = value.unwrapped,
              let interpretation,
              case .object(let type, let fields) = interpretation.unwrapped,
              type.hasPrefix("Binary property list v17") else {
            return nil
        }
        return fields.first(where: { $0.name == "Decoded value" })?.value
    }
}

public struct FoundationNSXPCBodyInspector: TraceBodyInspector {
    public let identifier = StandardBodyInspectorID.foundationNSXPC
    public let parentIdentifier: String? = StandardBodyInspectorID.rawXPC
    public let priority = 100

    public init() {}

    public func inspect(_ context: BodyInspectorContext) -> BodyInspection? {
        guard let parent = context.inspection(parentIdentifier!),
              let envelope = FoundationXPCEnvelopeDecoder.decode(parent.body) else {
            return nil
        }

        var summary: [String] = []
        if let operation = envelope.operation { summary.append(operation) }
        if !envelope.replyObjectTypes.isEmpty {
            summary.append("reply: \(envelope.replyObjectTypes.joined(separator: ", "))")
        }

        var metadata = envelope.metadata
        if let signature = envelope.invocationSignature {
            metadata.append(TraceField(name: "Invocation signature", value: .string(signature)))
        }
        if let replySignature = envelope.replySignature {
            metadata.append(TraceField(name: "Reply signature", value: .string(replySignature)))
        }

        return BodyInspection(
            id: identifier,
            name: "Foundation NSXPC",
            priority: priority,
            parentID: parentIdentifier,
            body: envelope.logicalBody,
            title: "NSXPCConnection",
            summary: summary.isEmpty ? nil : summary.joined(separator: " → "),
            systemImage: "shippingbox.and.arrow.backward",
            metadata: metadata
        )
    }
}

private extension TraceValue {
    var unwrapped: TraceValue {
        if case .sourced(_, let nested) = self { return nested.unwrapped }
        return self
    }

    var unsignedValue: UInt64? {
        switch unwrapped {
        case .unsigned(let value): value
        case .signed(let value) where value >= 0: UInt64(value)
        default: nil
        }
    }

    var plainString: String? {
        if case .string(let value) = unwrapped { return value }
        return nil
    }
}

private extension [TraceField] {
    func unsignedValue(named name: String) -> UInt64? {
        first(where: { $0.name == name })?.value.unsignedValue
    }

    func stringValue(named name: String) -> String? {
        first(where: { $0.name == name })?.value.plainString
    }
}
