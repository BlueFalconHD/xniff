import Foundation

public struct RawXPCBodyInspector: TraceBodyInspector {
    public let identifier = StandardBodyInspectorID.rawXPC
    public let parentIdentifier: String? = StandardBodyInspectorID.hex
    public let priority = 0

    public init() {}

    public func inspect(_ context: BodyInspectorContext) -> BodyInspection? {
        BodyInspection(
            id: identifier,
            name: "Raw XPC",
            priority: priority,
            parentID: parentIdentifier,
            content: .tree(context.originalBody)
        )
    }
}
