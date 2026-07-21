import Foundation

public struct HexBodyInspector: TraceBodyInspector {
    public let identifier = StandardBodyInspectorID.hex
    public let parentIdentifier: String? = nil
    public let priority = -100

    public init() {}

    public func inspect(_ context: BodyInspectorContext) -> BodyInspection? {
        BodyInspection(
            id: identifier,
            name: "Hex",
            priority: priority,
            parentID: parentIdentifier,
            content: .bytes(context.originalData)
        )
    }
}
