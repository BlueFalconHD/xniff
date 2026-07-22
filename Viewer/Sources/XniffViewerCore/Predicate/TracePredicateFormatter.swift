import Foundation

public enum TracePredicateFormatter {
    public static func string(from predicate: TracePredicate) -> String {
        guard !predicate.root.items.isEmpty else { return "" }
        return format(group: predicate.root, isRoot: true)
    }

    private static func format(group: TracePredicateGroup, isRoot: Bool) -> String {
        let separator = " \(group.conjunction.rawValue) "
        let body = group.items.map(format(item:)).joined(separator: separator)
        let grouped = isRoot && !group.isNegated ? body : "(\(body))"
        return group.isNegated ? "not \(grouped)" : grouped
    }

    private static func format(item: TracePredicateItem) -> String {
        switch item {
        case .comparison(let comparison):
            let body = format(comparison: comparison)
            return comparison.isNegated ? "not \(body)" : body
        case .group(let group):
            return format(group: group, isRoot: false)
        }
    }

    private static func format(comparison: TracePredicateComparison) -> String {
        let prefix = "\(comparison.field.rawValue) \(operatorText(comparison.operation))"
        guard comparison.operation.requiresValue else { return prefix }
        return "\(prefix) \(literalText(comparison.value))"
    }

    private static func operatorText(_ operation: TracePredicateOperator) -> String {
        switch operation {
        case .equals: "=="
        case .notEquals: "!="
        case .contains: "contains"
        case .notContains: "not contains"
        case .beginsWith: "beginswith"
        case .endsWith: "endswith"
        case .matches: "matches"
        case .lessThan: "<"
        case .lessThanOrEqual: "<="
        case .greaterThan: ">"
        case .greaterThanOrEqual: ">="
        case .exists: "exists"
        case .notExists: "not exists"
        }
    }

    private static func literalText(_ literal: TracePredicateLiteral) -> String {
        switch literal {
        case .string(let value):
            let escaped = value
                .replacingOccurrences(of: "\\", with: "\\\\")
                .replacingOccurrences(of: "\"", with: "\\\"")
                .replacingOccurrences(of: "\n", with: "\\n")
                .replacingOccurrences(of: "\t", with: "\\t")
            return "\"\(escaped)\""
        case .number(let value):
            return NSDecimalNumber(decimal: value).stringValue
        case .boolean(let value):
            return value ? "true" : "false"
        }
    }
}
