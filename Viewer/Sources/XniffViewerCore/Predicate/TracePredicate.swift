import Foundation

public struct TracePredicate: Sendable, Equatable {
    public var root: TracePredicateGroup

    public init(root: TracePredicateGroup = TracePredicateGroup()) {
        self.root = root
    }

    public static var all: TracePredicate { TracePredicate() }

    public var isEmpty: Bool { root.items.isEmpty }

    public var text: String {
        TracePredicateFormatter.string(from: self)
    }

    public mutating func conjoin(_ item: TracePredicateItem) {
        guard !isEmpty else {
            root.items = [item]
            return
        }
        if root.conjunction == .and, !root.isNegated {
            root.items.append(item)
        } else {
            let previous = TracePredicateItem.group(root)
            root = TracePredicateGroup(conjunction: .and, items: [previous, item])
        }
    }
}

public struct TracePredicateGroup: Sendable, Equatable, Identifiable {
    public let id: UUID
    public var conjunction: TracePredicateConjunction
    public var isNegated: Bool
    public var items: [TracePredicateItem]

    public init(
        id: UUID = UUID(),
        conjunction: TracePredicateConjunction = .and,
        isNegated: Bool = false,
        items: [TracePredicateItem] = []
    ) {
        self.id = id
        self.conjunction = conjunction
        self.isNegated = isNegated
        self.items = items
    }
}

public enum TracePredicateConjunction: String, CaseIterable, Sendable, Equatable, Identifiable {
    case and
    case or

    public var id: String { rawValue }
    public var label: String { self == .and ? "All" : "Any" }
}

public indirect enum TracePredicateItem: Sendable, Equatable, Identifiable {
    case comparison(TracePredicateComparison)
    case group(TracePredicateGroup)

    public var id: UUID {
        switch self {
        case .comparison(let comparison): comparison.id
        case .group(let group): group.id
        }
    }

    public var isNegated: Bool {
        get {
            switch self {
            case .comparison(let comparison): comparison.isNegated
            case .group(let group): group.isNegated
            }
        }
        set {
            switch self {
            case .comparison(var comparison):
                comparison.isNegated = newValue
                self = .comparison(comparison)
            case .group(var group):
                group.isNegated = newValue
                self = .group(group)
            }
        }
    }
}

public struct TracePredicateComparison: Sendable, Equatable, Identifiable {
    public let id: UUID
    public var field: TracePredicateField
    public var operation: TracePredicateOperator
    public var value: TracePredicateLiteral
    public var isNegated: Bool

    public init(
        id: UUID = UUID(),
        field: TracePredicateField = .service,
        operation: TracePredicateOperator = .contains,
        value: TracePredicateLiteral = .string(""),
        isNegated: Bool = false
    ) {
        self.id = id
        self.field = field
        self.operation = operation
        self.value = value
        self.isNegated = isNegated
    }

    public static func equals(
        _ field: TracePredicateField,
        _ value: TracePredicateLiteral
    ) -> TracePredicateComparison {
        TracePredicateComparison(field: field, operation: .equals, value: value)
    }
}

public struct TracePredicateField: RawRepresentable, Sendable, Hashable, Identifiable {
    public let rawValue: String

    public init(rawValue: String) {
        self.rawValue = rawValue
    }

    public var id: String { rawValue }

    public static let any = field("any")
    public static let callID = field("call.id")
    public static let processID = field("pid")
    public static let peerProcessID = field("peer.pid")
    public static let role = field("role")
    public static let service = field("service")
    public static let function = field("function")
    public static let functionID = field("function.id")
    public static let api = field("api")
    public static let direction = field("direction")
    public static let timestamp = field("timestamp")
    public static let duration = field("duration")
    public static let complete = field("complete")
    public static let requestExists = field("request.exists")
    public static let responseExists = field("response.exists")
    public static let eventCount = field("event.count")
    public static let eventID = field("event.id")
    public static let sequence = field("sequence")
    public static let threadID = field("thread.id")
    public static let returnValue = field("return.value")
    public static let argument = field("argument")
    public static let summary = field("summary")
    public static let xpcObject = field("xpc.object")
    public static let xpcKind = field("xpc.kind")
    public static let xpcLifecycle = field("xpc.lifecycle")
    public static let payloadCount = field("payload.count")
    public static let payloadSize = field("payload.size")
    public static let payloadKind = field("payload.kind")
    public static let payloadTruncated = field("payload.truncated")
    public static let backtraceImage = field("backtrace.image")
    public static let backtraceSymbol = field("backtrace.symbol")
    public static let inspector = field("inspector")
    public static let tree = field("tree")
    public static let requestTree = field("request.tree")
    public static let responseTree = field("response.tree")
    public static let treePath = field("tree.path")
    public static let treeName = field("tree.name")
    public static let treeValue = field("tree.value")
    public static let treeNumber = field("tree.number")
    public static let treeBoolean = field("tree.boolean")
    public static let treeType = field("tree.type")

    public static let all: [TracePredicateField] = [
        .any, .callID, .processID, .peerProcessID, .role, .service, .function,
        .functionID, .api, .direction, .timestamp, .duration, .complete,
        .requestExists, .responseExists, .eventCount, .eventID, .sequence,
        .threadID, .returnValue, .argument, .summary, .xpcObject, .xpcKind,
        .xpcLifecycle, .payloadCount, .payloadSize, .payloadKind,
        .payloadTruncated, .backtraceImage, .backtraceSymbol, .inspector, .tree,
        .requestTree, .responseTree, .treePath, .treeName, .treeValue,
        .treeNumber, .treeBoolean, .treeType,
    ]

    public var label: String {
        switch self {
        case .any: "Any metadata"
        case .callID: "Call ID"
        case .processID: "Process ID"
        case .peerProcessID: "Peer process ID"
        case .role: "Role"
        case .service: "Service"
        case .function: "Function"
        case .functionID: "Function ID"
        case .api: "API"
        case .direction: "Direction"
        case .timestamp: "Timestamp"
        case .duration: "Duration"
        case .complete: "Complete pair"
        case .requestExists: "Has request"
        case .responseExists: "Has response"
        case .eventCount: "Event count"
        case .eventID: "Event ID"
        case .sequence: "Sequence"
        case .threadID: "Thread ID"
        case .returnValue: "Return value"
        case .argument: "Argument"
        case .summary: "Summary"
        case .xpcObject: "XPC object"
        case .xpcKind: "XPC kind"
        case .xpcLifecycle: "XPC lifecycle"
        case .payloadCount: "Payload count"
        case .payloadSize: "Payload size"
        case .payloadKind: "Payload kind"
        case .payloadTruncated: "Payload truncated"
        case .backtraceImage: "Backtrace image"
        case .backtraceSymbol: "Backtrace symbol"
        case .inspector: "Inspector"
        case .tree: "Any inspector tree"
        case .requestTree: "Request tree"
        case .responseTree: "Response tree"
        case .treePath: "Tree path"
        case .treeName: "Tree field name"
        case .treeValue: "Tree value"
        case .treeNumber: "Tree numeric value"
        case .treeBoolean: "Tree Boolean value"
        case .treeType: "Tree object type"
        default: rawValue
        }
    }

    public var valueKind: TracePredicateValueKind {
        switch self {
        case .callID, .processID, .peerProcessID, .functionID, .timestamp,
             .duration, .eventCount, .eventID, .sequence, .threadID,
             .returnValue, .argument, .xpcObject, .payloadCount, .payloadSize,
             .treeNumber:
            .number
        case .complete, .requestExists, .responseExists, .payloadTruncated,
             .treeBoolean:
            .boolean
        default:
            .string
        }
    }

    public var requiresBodyData: Bool {
        switch self {
        case .inspector, .tree, .requestTree, .responseTree, .treePath,
             .treeName, .treeValue, .treeNumber, .treeBoolean, .treeType:
            true
        default:
            false
        }
    }

    public static func recognized(_ name: String) -> TracePredicateField? {
        let normalized = name.lowercased()
        if let exact = all.first(where: { $0.rawValue == normalized }) {
            return exact
        }
        let aliases: [String: TracePredicateField] = [
            "time": .timestamp,
            "type": .role,
            "peer_pid": .peerProcessID,
            "call_id": .callID,
            "tid": .threadID,
            "retval": .returnValue,
            "body": .tree,
        ]
        return aliases[normalized]
    }

    private static func field(_ rawValue: String) -> TracePredicateField {
        TracePredicateField(rawValue: rawValue)
    }
}

public enum TracePredicateValueKind: Sendable, Equatable {
    case string
    case number
    case boolean
}

public enum TracePredicateOperator: String, CaseIterable, Sendable, Equatable, Identifiable {
    case equals
    case notEquals
    case contains
    case notContains
    case beginsWith
    case endsWith
    case matches
    case lessThan
    case lessThanOrEqual
    case greaterThan
    case greaterThanOrEqual
    case exists
    case notExists

    public var id: String { rawValue }

    public var label: String {
        switch self {
        case .equals: "is"
        case .notEquals: "is not"
        case .contains: "contains"
        case .notContains: "does not contain"
        case .beginsWith: "begins with"
        case .endsWith: "ends with"
        case .matches: "matches regex"
        case .lessThan: "is less than"
        case .lessThanOrEqual: "is at most"
        case .greaterThan: "is greater than"
        case .greaterThanOrEqual: "is at least"
        case .exists: "exists"
        case .notExists: "does not exist"
        }
    }

    public var requiresValue: Bool {
        ![.exists, .notExists].contains(self)
    }

    public static func supported(for kind: TracePredicateValueKind) -> [TracePredicateOperator] {
        switch kind {
        case .string:
            [.equals, .notEquals, .contains, .notContains, .beginsWith,
             .endsWith, .matches, .exists, .notExists]
        case .number:
            [.equals, .notEquals, .lessThan, .lessThanOrEqual, .greaterThan,
             .greaterThanOrEqual, .exists, .notExists]
        case .boolean:
            [.equals, .notEquals, .exists, .notExists]
        }
    }
}

public enum TracePredicateLiteral: Sendable, Equatable {
    case string(String)
    case number(Decimal)
    case boolean(Bool)

    public static func defaultValue(for kind: TracePredicateValueKind) -> TracePredicateLiteral {
        switch kind {
        case .string: .string("")
        case .number: .number(0)
        case .boolean: .boolean(true)
        }
    }
}
