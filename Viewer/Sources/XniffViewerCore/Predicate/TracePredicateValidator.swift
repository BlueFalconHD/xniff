import Foundation

public enum TracePredicateValidator {
    public static func firstError(in predicate: TracePredicate) -> String? {
        firstError(in: predicate.root)
    }

    private static func firstError(in group: TracePredicateGroup) -> String? {
        for item in group.items {
            switch item {
            case .group(let nested):
                if let error = firstError(in: nested) { return error }
            case .comparison(let comparison):
                if let error = firstError(in: comparison) { return error }
            }
        }
        return nil
    }

    private static func firstError(in comparison: TracePredicateComparison) -> String? {
        let supported = TracePredicateOperator.supported(for: comparison.field.valueKind)
        guard supported.contains(comparison.operation) else {
            return "\(comparison.operation.label) is not valid for \(comparison.field.label)."
        }
        guard comparison.operation.requiresValue else { return nil }
        guard comparison.value.kind == comparison.field.valueKind else {
            return "\(comparison.field.label) has an incompatible value."
        }
        if comparison.operation == .matches,
           case .string(let pattern) = comparison.value,
           (try? NSRegularExpression(pattern: pattern)) == nil {
            return "The regular expression for \(comparison.field.label) is invalid."
        }
        return nil
    }
}

public extension TracePredicate {
    var validationError: String? {
        TracePredicateValidator.firstError(in: self)
    }
}

private extension TracePredicateLiteral {
    var kind: TracePredicateValueKind {
        switch self {
        case .string: .string
        case .number: .number
        case .boolean: .boolean
        }
    }
}
