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
        var details: [BodyInspectionDetail] = [
            BodyInspectionDetail("Frame", value: envelope.frameKind.label)
        ]
        if let signature = envelope.replySignature {
            details.append(BodyInspectionDetail("Reply signature", value: signature))
        }
        if let flags = envelope.flags {
            let labels = envelope.flagSet.labels
            let suffix = labels.isEmpty ? "" : " (\(labels.joined(separator: ", ")))"
            details.append(BodyInspectionDetail("Flags", value: String(format: "0x%llX", flags) + suffix))
        }
        if let proxyNumber = envelope.proxyNumber {
            details.append(BodyInspectionDetail("Proxy", value: String(proxyNumber)))
        }
        if let sequence = envelope.sequence {
            details.append(BodyInspectionDetail("Sequence", value: String(sequence)))
        }
        if !envelope.outOfLineObjects.isEmpty {
            details.append(BodyInspectionDetail(
                "Out-of-line objects",
                value: String(envelope.outOfLineObjects.count)
            ))
        }
        if !envelope.validationIssues.isEmpty {
            details.append(BodyInspectionDetail(
                "Validation",
                value: envelope.validationIssues.joined(separator: ", ")
            ))
        }
        return details
    }
}
