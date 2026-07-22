import Foundation

public struct FoundationXPCEnvelope: Sendable {
    public let frameKind: FoundationXPCFrameKind
    public let decodedRoot: TraceValue?
    public let invocation: FoundationXPCInvocation?
    public let metadata: [TraceField]
    public let flags: UInt64?
    public let proxyNumber: UInt64?
    public let sequence: UInt64?
    public let replySignature: String?
    public let parsedReplySignature: ObjectiveCMethodSignature?
    public let outOfLineObjects: [TraceValue]
    public let validationIssues: [String]

    public var flagSet: FoundationXPCFlags { FoundationXPCFlags(rawValue: flags ?? 0) }
    public var logicalBody: TraceValue { invocation?.semanticBody ?? decodedRoot ?? controlBody }
    public var operation: String? { invocation?.selector }
    public var invocationSignature: String? { invocation?.signatureEncoding }
    public var replyObjectTypes: [String] {
        guard let parsedReplySignature else { return [] }
        return parsedReplySignature.arguments.dropFirst().compactMap(\.type.objectClassName)
    }

    public init(
        decodedRoot: TraceValue,
        metadata: [TraceField],
        flags: UInt64?,
        proxyNumber: UInt64?,
        sequence: UInt64?,
        replySignature: String?
    ) {
        let invocation = FoundationXPCInvocation(decodedRoot: decodedRoot)
        self.frameKind = invocation.map {
            $0.kind == .request ? .request : .reply
        } ?? .invalidInvocation
        self.decodedRoot = decodedRoot
        self.invocation = invocation
        self.metadata = metadata
        self.flags = flags
        self.proxyNumber = proxyNumber
        self.sequence = sequence
        self.replySignature = replySignature
        self.parsedReplySignature = replySignature.flatMap(ObjectiveCMethodSignature.parse)
        self.outOfLineObjects = []
        self.validationIssues = invocation?.validationIssues ?? ["Archive is not an NSXPC invocation"]
    }

    init(
        frameKind: FoundationXPCFrameKind,
        decodedRoot: TraceValue?,
        invocation: FoundationXPCInvocation?,
        metadata: [TraceField],
        flags: UInt64?,
        proxyNumber: UInt64?,
        sequence: UInt64?,
        replySignature: String?,
        outOfLineObjects: [TraceValue],
        validationIssues: [String]
    ) {
        self.frameKind = frameKind
        self.decodedRoot = decodedRoot
        self.invocation = invocation
        self.metadata = metadata
        self.flags = flags
        self.proxyNumber = proxyNumber
        self.sequence = sequence
        self.replySignature = replySignature
        self.parsedReplySignature = replySignature.flatMap(ObjectiveCMethodSignature.parse)
        self.outOfLineObjects = outOfLineObjects
        self.validationIssues = validationIssues
    }

    private var controlBody: TraceValue {
        var fields: [TraceField] = []
        if let proxyNumber {
            fields.append(TraceField(name: "Proxy number", value: .unsigned(proxyNumber)))
        }
        if let sequence {
            fields.append(TraceField(name: "Sequence", value: .unsigned(sequence)))
        }
        fields.append(contentsOf: metadata.filter {
            !["f", "proxynum", "sequence"].contains($0.name)
        })
        return .object(type: "NSXPC \(frameKind.rawValue)", fields: fields)
    }
}
