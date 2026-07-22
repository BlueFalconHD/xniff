import Foundation

public typealias TracePredicateBodyLoader = @Sendable () async -> TracePredicateBodyIndex

public enum TracePredicateEvaluator {
    public static func matches(
        _ predicate: TracePredicate,
        call: TraceCall,
        bodyLoader: TracePredicateBodyLoader? = nil
    ) async throws -> Bool {
        guard !predicate.isEmpty else { return true }
        let body = LazyBodyIndex(loader: bodyLoader)
        return try await evaluate(predicate.root, call: call, body: body)
    }

    private static func evaluate(
        _ group: TracePredicateGroup,
        call: TraceCall,
        body: LazyBodyIndex
    ) async throws -> Bool {
        try Task.checkCancellation()
        var result = group.conjunction == .and
        for item in group.items {
            let itemResult = try await evaluate(item, call: call, body: body)
            if group.conjunction == .and, !itemResult {
                result = false
                break
            }
            if group.conjunction == .or, itemResult {
                result = true
                break
            }
        }
        return group.isNegated ? !result : result
    }

    private static func evaluate(
        _ item: TracePredicateItem,
        call: TraceCall,
        body: LazyBodyIndex
    ) async throws -> Bool {
        switch item {
        case .group(let group):
            return try await evaluate(group, call: call, body: body)
        case .comparison(let comparison):
            try Task.checkCancellation()
            let values: [TracePredicateScalar]
            if comparison.field.requiresBodyData {
                values = await body.load()?.values(for: comparison.field) ?? []
                try Task.checkCancellation()
            } else {
                values = metadataValues(for: comparison.field, call: call)
            }
            let result = compare(values, using: comparison)
            return comparison.isNegated ? !result : result
        }
    }

    private static func compare(
        _ values: [TracePredicateScalar],
        using comparison: TracePredicateComparison
    ) -> Bool {
        switch comparison.operation {
        case .exists:
            return !values.isEmpty
        case .notExists:
            return values.isEmpty
        case .notEquals:
            return !values.contains { equals($0, comparison.value) }
        case .notContains:
            return !values.contains { contains($0, comparison.value) }
        case .matches:
            guard case .string(let pattern) = comparison.value,
                  let expression = try? NSRegularExpression(
                    pattern: pattern,
                    options: .caseInsensitive
                  ) else { return false }
            return values.contains { candidate in
                guard case .string(let candidate) = candidate else { return false }
                let range = NSRange(candidate.startIndex..<candidate.endIndex, in: candidate)
                return expression.firstMatch(in: candidate, range: range) != nil
            }
        default:
            return values.contains { candidate in
                compare(candidate, comparison.operation, comparison.value)
            }
        }
    }

    private static func compare(
        _ candidate: TracePredicateScalar,
        _ operation: TracePredicateOperator,
        _ literal: TracePredicateLiteral
    ) -> Bool {
        switch operation {
        case .equals:
            return equals(candidate, literal)
        case .contains:
            return contains(candidate, literal)
        case .beginsWith:
            guard let (candidate, literal) = strings(candidate, literal) else { return false }
            return candidate.localizedCaseInsensitiveHasPrefix(literal)
        case .endsWith:
            guard let (candidate, literal) = strings(candidate, literal) else { return false }
            return candidate.localizedCaseInsensitiveHasSuffix(literal)
        case .matches:
            return false
        case .lessThan, .lessThanOrEqual, .greaterThan, .greaterThanOrEqual:
            guard case .number(let candidate) = candidate,
                  case .number(let literal) = literal else { return false }
            let comparison = NSDecimalNumber(decimal: candidate)
                .compare(NSDecimalNumber(decimal: literal))
            switch operation {
            case .lessThan: return comparison == .orderedAscending
            case .lessThanOrEqual: return comparison != .orderedDescending
            case .greaterThan: return comparison == .orderedDescending
            case .greaterThanOrEqual: return comparison != .orderedAscending
            default: return false
            }
        case .notEquals, .notContains, .exists, .notExists:
            return false
        }
    }

    private static func equals(
        _ candidate: TracePredicateScalar,
        _ literal: TracePredicateLiteral
    ) -> Bool {
        switch (candidate, literal) {
        case (.string(let candidate), .string(let literal)):
            candidate.caseInsensitiveCompare(literal) == .orderedSame
        case (.number(let candidate), .number(let literal)):
            candidate == literal
        case (.boolean(let candidate), .boolean(let literal)):
            candidate == literal
        default:
            false
        }
    }

    private static func contains(
        _ candidate: TracePredicateScalar,
        _ literal: TracePredicateLiteral
    ) -> Bool {
        guard let (candidate, literal) = strings(candidate, literal) else { return false }
        return candidate.localizedCaseInsensitiveContains(literal)
    }

    private static func strings(
        _ candidate: TracePredicateScalar,
        _ literal: TracePredicateLiteral
    ) -> (String, String)? {
        guard case .string(let candidate) = candidate,
              case .string(let literal) = literal else { return nil }
        return (candidate, literal)
    }

    private static func metadataValues(
        for field: TracePredicateField,
        call: TraceCall
    ) -> [TracePredicateScalar] {
        switch field {
        case .any:
            let eventMetadata = call.events.flatMap { event in
                [
                    event.api.label,
                    event.direction.label,
                    event.summary,
                    String(event.sequence),
                    String(event.threadID),
                    String(event.returnValue),
                ] + event.arguments.map(String.init)
            }
            return [.string(([call.searchableText] + eventMetadata).joined(separator: " "))]
        case .callID:
            return [.number(decimal(call.id.callID))]
        case .processID:
            return [.number(decimal(call.processID))]
        case .peerProcessID:
            return call.peerProcessID.map { [.number(decimal($0))] } ?? []
        case .role:
            return [.string(call.role.rawValue)]
        case .service:
            return call.serviceName.map { [.string($0)] } ?? []
        case .function:
            return [.string(call.functionName)]
        case .functionID:
            return call.events.map { .number(decimal($0.function)) }
        case .api:
            return call.events.map { .string($0.api.label) }
        case .direction:
            return call.events.map { .string($0.direction.label) }
        case .timestamp:
            return [.number(decimal(call.relativeSeconds))]
        case .duration:
            return call.durationSeconds.map { [.number(decimal($0))] } ?? []
        case .complete:
            return [.boolean(call.isComplete)]
        case .requestExists:
            return [.boolean(call.request != nil)]
        case .responseExists:
            return [.boolean(call.response != nil)]
        case .eventCount:
            return [.number(decimal(call.events.count))]
        case .eventID:
            return call.events.map { .number(decimal($0.id)) }
        case .sequence:
            return call.events.map { .number(decimal($0.sequence)) }
        case .threadID:
            return call.events.map { .number(decimal($0.threadID)) }
        case .returnValue:
            return call.events.map { .number(decimal($0.returnValue)) }
        case .argument:
            return call.events.flatMap(\.arguments).map { .number(decimal($0)) }
        case .summary:
            return call.events.map { .string($0.summary) }
        case .xpcObject:
            return call.events.compactMap(\.xpcObjectID).map { .number(decimal($0)) }
        case .xpcKind:
            return call.events.compactMap { event -> TracePredicateScalar? in
                switch event.xpcObjectKind {
                case .connection: .string("connection")
                case .session: .string("session")
                case nil: nil
                }
            }
        case .xpcLifecycle:
            return call.events.compactMap { event -> TracePredicateScalar? in
                switch event.xpcObjectLifecycle {
                case .observed: .string("observed")
                case .created: .string("created")
                case .cancelled: .string("cancelled")
                case nil: nil
                }
            }
        case .payloadCount:
            let count = call.events.reduce(0) { $0 + $1.payloads.count }
            return [.number(decimal(count))]
        case .payloadSize:
            return call.events.flatMap(\.payloads).map { .number(decimal($0.range.count)) }
        case .payloadKind:
            return call.events.flatMap(\.payloads).map { .string($0.kind.label) }
        case .payloadTruncated:
            return call.events.flatMap(\.payloads).map { .boolean($0.isTruncated) }
        case .backtraceImage:
            return call.events.flatMap(\.backtrace).compactMap(\.imagePath).map {
                .string($0)
            }
        case .backtraceSymbol:
            return call.events.flatMap(\.backtrace).compactMap(\.symbolName).map {
                .string($0)
            }
        default:
            return []
        }
    }

    private static func decimal<T: CustomStringConvertible>(_ value: T) -> Decimal {
        Decimal(string: value.description, locale: Locale(identifier: "en_US_POSIX")) ?? 0
    }
}

private actor LazyBodyIndex {
    private let loader: TracePredicateBodyLoader?
    private var cached: TracePredicateBodyIndex?

    init(loader: TracePredicateBodyLoader?) {
        self.loader = loader
    }

    func load() async -> TracePredicateBodyIndex? {
        if let cached { return cached }
        guard let loader else { return nil }
        let loaded = await loader()
        cached = loaded
        return loaded
    }
}

private extension String {
    func localizedCaseInsensitiveHasPrefix(_ prefix: String) -> Bool {
        range(of: prefix, options: [.anchored, .caseInsensitive, .diacriticInsensitive]) != nil
    }

    func localizedCaseInsensitiveHasSuffix(_ suffix: String) -> Bool {
        guard suffix.count <= count else { return false }
        let start = index(endIndex, offsetBy: -suffix.count)
        return self[start...].compare(suffix, options: [.caseInsensitive, .diacriticInsensitive]) == .orderedSame
    }
}
