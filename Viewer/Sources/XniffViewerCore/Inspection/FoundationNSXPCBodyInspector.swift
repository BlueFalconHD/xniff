import Foundation

public struct FoundationNSXPCBodyInspector: TraceBodyInspector {
    public let identifier = StandardBodyInspectorID.foundationNSXPC
    public let parentIdentifier: String? = StandardBodyInspectorID.rawXPC
    public let priority = 100

    public init() {}

    public func inspect(_ context: BodyInspectorContext) -> BodyInspection? {
        guard let parentIdentifier,
              let parentBody = context.inspection(parentIdentifier)?.tree,
              let envelope = FoundationXPCEnvelopeDecoder.decode(parentBody) else {
            return nil
        }

        return BodyInspection(
            id: identifier,
            name: "Foundation NSXPC",
            priority: priority,
            parentID: parentIdentifier,
            content: .tree(envelope.logicalBody),
            details: details(for: envelope)
        )
    }

    private func details(for envelope: FoundationXPCEnvelope) -> [BodyInspectionDetail] {
        var details: [BodyInspectionDetail] = []
        if let operation = envelope.operation {
            details.append(BodyInspectionDetail("Operation", value: operation))
        }
        if let signature = envelope.invocationSignature {
            details.append(BodyInspectionDetail("Invocation signature", value: signature))
        }
        if let signature = envelope.replySignature {
            details.append(BodyInspectionDetail("Reply signature", value: signature))
        }
        if !envelope.replyObjectTypes.isEmpty {
            details.append(BodyInspectionDetail(
                "Reply object types",
                value: envelope.replyObjectTypes.joined(separator: ", ")
            ))
        }
        if let flags = envelope.flags {
            details.append(BodyInspectionDetail("Flags", value: String(format: "0x%llX", flags)))
        }
        if let proxyNumber = envelope.proxyNumber {
            details.append(BodyInspectionDetail("Proxy", value: String(proxyNumber)))
        }
        if let sequence = envelope.sequence {
            details.append(BodyInspectionDetail("Sequence", value: String(sequence)))
        }
        return details
    }
}
