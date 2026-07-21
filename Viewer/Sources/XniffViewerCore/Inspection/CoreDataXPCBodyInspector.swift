import Foundation

public struct CoreDataXPCBodyInspector: TraceBodyInspector {
    public let identifier = StandardBodyInspectorID.coreDataXPC
    public let parentIdentifier: String? = StandardBodyInspectorID.foundationNSXPC
    public let priority = 200

    public init() {}

    public func inspect(_ context: BodyInspectorContext) -> BodyInspection? {
        guard let parentIdentifier,
              let parentBody = context.inspection(parentIdentifier)?.tree,
              let message = CoreDataXPCMessageDecoder.decode(parentBody) else {
            return nil
        }

        return BodyInspection(
            id: identifier,
            name: "Core Data",
            priority: priority,
            parentID: parentIdentifier,
            content: .tree(message.logicalBody),
            details: details(for: message)
        )
    }

    private func details(for message: CoreDataXPCMessage) -> [BodyInspectionDetail] {
        var details = [BodyInspectionDetail("Operation", value: message.operationName)]
        if let code = message.code {
            details.append(BodyInspectionDetail("Message code", value: String(code)))
        }
        if let token = message.token {
            details.append(BodyInspectionDetail("Token", value: token))
        }
        if let contextName = message.contextName {
            details.append(BodyInspectionDetail("Context", value: contextName))
        }
        if let transactionAuthor = message.transactionAuthor {
            details.append(BodyInspectionDetail("Transaction author", value: transactionAuthor))
        }
        if let processName = message.processName {
            details.append(BodyInspectionDetail("Process", value: processName))
        }
        if message.allowsAncillaryEntities {
            details.append(BodyInspectionDetail("Ancillary entities", value: "Allowed"))
        }
        return details
    }
}
