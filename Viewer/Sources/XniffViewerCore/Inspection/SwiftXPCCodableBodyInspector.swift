import Foundation

public struct SwiftXPCCodableBodyInspector: TraceBodyInspector {
    public let identifier = StandardBodyInspectorID.swiftXPCCodable
    public let parentIdentifier: String? = StandardBodyInspectorID.rawXPC
    public let priority = 150

    public init() {}

    public func inspect(_ context: BodyInspectorContext) -> BodyInspection? {
        guard let parentIdentifier,
              let parentBody = context.inspection(parentIdentifier)?.tree,
              let envelope = SwiftXPCCodableEnvelopeDecoder.decode(parentBody) else {
            return nil
        }

        var details: [BodyInspectionDetail] = []
        if let version = envelope.coderVersion {
            details.append(BodyInspectionDetail("Coder version", value: String(version)))
        }
        if let isSynchronous = envelope.isSynchronous {
            details.append(BodyInspectionDetail("Delivery", value: isSynchronous ? "Synchronous" : "Asynchronous"))
        }
        details.append(BodyInspectionDetail(
            "Out-of-line data",
            value: String(envelope.outOfLineObjects.count)
        ))
        details.append(BodyInspectionDetail(
            "Out-of-line Codable objects",
            value: String(envelope.codableObjects.count)
        ))
        if let decodingError = envelope.decodingError {
            details.append(BodyInspectionDetail("Decode error", value: decodingError))
        }

        return BodyInspection(
            id: identifier,
            name: "Swift XPC Codable",
            priority: priority,
            parentID: parentIdentifier,
            content: .tree(envelope.decodedBody),
            details: details
        )
    }
}
