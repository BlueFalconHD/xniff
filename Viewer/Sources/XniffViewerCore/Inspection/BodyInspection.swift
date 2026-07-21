import Foundation

public struct BodyInspection: Sendable, Identifiable {
    public let id: String
    public let name: String
    public let priority: Int
    public let parentID: String?
    public let body: TraceValue
    public let title: String
    public let summary: String?
    public let systemImage: String
    public let metadata: [TraceField]

    public init(
        id: String,
        name: String,
        priority: Int,
        parentID: String?,
        body: TraceValue,
        title: String,
        summary: String? = nil,
        systemImage: String = "doc.text.magnifyingglass",
        metadata: [TraceField] = []
    ) {
        self.id = id
        self.name = name
        self.priority = priority
        self.parentID = parentID
        self.body = body
        self.title = title
        self.summary = summary
        self.systemImage = systemImage
        self.metadata = metadata
    }
}

public struct BodyInspectorContext: Sendable {
    public let originalBody: TraceValue
    public let inspections: [String: BodyInspection]

    public init(originalBody: TraceValue, inspections: [String: BodyInspection]) {
        self.originalBody = originalBody
        self.inspections = inspections
    }

    public func inspection(_ id: String) -> BodyInspection? {
        inspections[id]
    }
}

public protocol TraceBodyInspector: Sendable {
    var identifier: String { get }
    var parentIdentifier: String? { get }
    var priority: Int { get }

    func inspect(_ context: BodyInspectorContext) -> BodyInspection?
}

public enum StandardBodyInspectorID {
    public static let rawXPC = "xniff.raw-xpc"
    public static let foundationNSXPC = "xniff.foundation-nsxpc"
    public static let coreDataXPC = "xniff.core-data-xpc"
}
