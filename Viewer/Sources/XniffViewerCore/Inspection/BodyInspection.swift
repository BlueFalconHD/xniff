import Foundation

public enum BodyInspectionContent: Sendable, Equatable {
    case bytes(Data)
    case tree(TraceValue)
}

public struct BodyInspectionDetail: Sendable, Equatable, Identifiable {
    public let label: String
    public let value: String

    public var id: String { label }

    public init(_ label: String, value: String) {
        self.label = label
        self.value = value
    }
}

public struct BodyInspection: Sendable, Identifiable {
    public let id: String
    public let name: String
    public let priority: Int
    public let parentID: String?
    public let content: BodyInspectionContent
    public let details: [BodyInspectionDetail]

    public var tree: TraceValue? {
        guard case .tree(let value) = content else { return nil }
        return value
    }

    public init(
        id: String,
        name: String,
        priority: Int,
        parentID: String?,
        content: BodyInspectionContent,
        details: [BodyInspectionDetail] = []
    ) {
        self.id = id
        self.name = name
        self.priority = priority
        self.parentID = parentID
        self.content = content
        self.details = details
    }
}

public struct BodyInspectorContext: Sendable {
    public let originalBody: TraceValue
    public let originalData: Data
    public let inspections: [String: BodyInspection]

    public init(
        originalBody: TraceValue,
        originalData: Data,
        inspections: [String: BodyInspection]
    ) {
        self.originalBody = originalBody
        self.originalData = originalData
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
    public static let hex = "xniff.hex"
    public static let rawXPC = "xniff.raw-xpc"
    public static let foundationNSXPC = "xniff.foundation-nsxpc"
    public static let coreDataXPC = "xniff.core-data-xpc"
}
