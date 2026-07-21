import Foundation

public struct BodyInspectorRegistry: Sendable {
    public static let standard = BodyInspectorRegistry(inspectors: [
        HexBodyInspector(),
        RawXPCBodyInspector(),
        FoundationNSXPCBodyInspector(),
        CoreDataXPCBodyInspector(),
    ])

    private let inspectors: [any TraceBodyInspector]

    public init(inspectors: [any TraceBodyInspector]) {
        self.inspectors = inspectors
    }

    public func inspections(for body: TraceValue, data: Data) -> [BodyInspection] {
        var available: [String: BodyInspection] = [:]
        var pending = inspectors.sorted { lhs, rhs in
            if lhs.priority == rhs.priority { return lhs.identifier < rhs.identifier }
            return lhs.priority < rhs.priority
        }

        while !pending.isEmpty {
            var deferred: [any TraceBodyInspector] = []
            var madeProgress = false

            for inspector in pending {
                if let parent = inspector.parentIdentifier, available[parent] == nil {
                    deferred.append(inspector)
                    continue
                }

                let context = BodyInspectorContext(
                    originalBody: body,
                    originalData: data,
                    inspections: available
                )
                if let result = inspector.inspect(context) {
                    available[inspector.identifier] = result
                }
                madeProgress = true
            }

            guard madeProgress else { break }
            pending = deferred
        }

        return available.values.sorted { lhs, rhs in
            if lhs.priority == rhs.priority { return lhs.name < rhs.name }
            return lhs.priority > rhs.priority
        }
    }
}
