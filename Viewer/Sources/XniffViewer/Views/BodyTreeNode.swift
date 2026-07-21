import Foundation
import XniffViewerCore

@MainActor
final class BodyTreeNode: NSObject {
    private struct Match {
        let path: [BodyTreeNode]
        let relation: Int
        let explicit: Bool
        let rangeLength: Int

        func isBetter(than other: Match) -> Bool {
            if relation != other.relation { return relation > other.relation }
            if explicit != other.explicit { return explicit }
            if rangeLength != other.rangeLength { return rangeLength < other.rangeLength }
            return explicit ? path.count > other.path.count : path.count < other.path.count
        }
    }

    let name: String
    let value: TraceValue
    let sourceRange: Range<Int>?
    let hasExplicitSourceRange: Bool
    let isPreview: Bool

    private var cachedChildren: [Int: BodyTreeNode] = [:]

    init(
        name: String,
        value: TraceValue,
        sourceRange: Range<Int>?,
        isPreview: Bool = false
    ) {
        let unwrapped = Self.unwrap(value, inheritedRange: sourceRange)
        self.name = name
        self.value = unwrapped.value
        self.sourceRange = unwrapped.range
        self.hasExplicitSourceRange = unwrapped.explicit
        self.isPreview = isPreview
    }

    static func error(index: Int) -> BodyTreeNode {
        BodyTreeNode(
            name: "Invalid child \(index)",
            value: .error("The decoded tree is inconsistent"),
            sourceRange: nil
        )
    }

    var childCount: Int {
        switch value {
        case .array(let values): values.count
        case .dictionary(let fields), .object(_, let fields): fields.count
        case .data(let data, let interpretation):
            (data.isEmpty ? 0 : 1) + (interpretation == nil ? 0 : 1)
        case .sourced: 0
        default: 0
        }
    }

    var detail: String {
        switch value {
        case .null: "null"
        case .bool(let value): value ? "true" : "false"
        case .signed(let value): String(value)
        case .unsigned(let value): String(value)
        case .double(let value): String(value)
        case .string(let value): value
        case .data(let data, _): "Data (\(data.count.formatted()) bytes)"
        case .array(let values): "Array (\(values.count.formatted()) items)"
        case .dictionary(let fields): "Dictionary (\(fields.count.formatted()) keys)"
        case .object(let type, _): type
        case .reference(let index): "↩︎ object \(index)"
        case .sourced(_, let nested): nested.summary
        case .error(let message): message
        }
    }

    var copyValue: String { detail.isEmpty ? name : detail }
    var isError: Bool { if case .error = value { true } else { false } }
    var isMonospaced: Bool {
        switch value {
        case .signed, .unsigned, .double, .reference: true
        default: false
        }
    }

    func child(at index: Int) -> BodyTreeNode {
        if let cached = cachedChildren[index] { return cached }
        let child = makeChild(at: index)
        cachedChildren[index] = child
        return child
    }

    func bestPath(matching target: Range<Int>) -> [BodyTreeNode]? {
        var best: Match?
        collectMatches(
            target: target,
            path: [self],
            includeSelf: childCount == 0,
            best: &best
        )
        return best?.path
    }

    private func collectMatches(
        target: Range<Int>,
        path: [BodyTreeNode],
        includeSelf: Bool,
        best: inout Match?
    ) {
        if includeSelf,
           !isPreview,
           let sourceRange,
           let relation = matchRelation(sourceRange, target: target) {
            let candidate = Match(
                path: path,
                relation: relation,
                explicit: hasExplicitSourceRange,
                rangeLength: sourceRange.count
            )
            if let current = best {
                if candidate.isBetter(than: current) { best = candidate }
            } else {
                best = candidate
            }
        }

        for index in 0..<childCount {
            let child = child(at: index)
            child.collectMatches(
                target: target,
                path: path + [child],
                includeSelf: true,
                best: &best
            )
        }
    }

    private func matchRelation(_ source: Range<Int>, target: Range<Int>) -> Int? {
        if source == target { return 3 }
        if source.lowerBound <= target.lowerBound && source.upperBound >= target.upperBound { return 2 }
        if source.overlaps(target) { return 1 }
        return nil
    }

    private func makeChild(at index: Int) -> BodyTreeNode {
        switch value {
        case .array(let values) where values.indices.contains(index):
            return BodyTreeNode(
                name: "[\(index)]",
                value: values[index],
                sourceRange: sourceRange
            )
        case .dictionary(let fields) where fields.indices.contains(index),
             .object(_, let fields) where fields.indices.contains(index):
            let field = fields[index]
            return BodyTreeNode(
                name: field.name,
                value: field.value,
                sourceRange: sourceRange
            )
        case .data(let data, let interpretation):
            if !data.isEmpty && index == 0 {
                let preview = data.prefix(48).map { String(format: "%02X", $0) }.joined()
                return BodyTreeNode(
                    name: preview + (data.count > 48 ? "…" : ""),
                    value: .string(""),
                    sourceRange: sourceRange,
                    isPreview: true
                )
            }
            if let interpretation {
                let interpretationIndex = data.isEmpty ? 0 : 1
                if index == interpretationIndex {
                    let decoded = Self.unwrap(interpretation, inheritedRange: sourceRange)
                    if case .object(let type, let fields) = decoded.value {
                        return BodyTreeNode(
                            name: type,
                            value: decoded.range.map {
                                .sourced(range: $0, value: .dictionary(fields))
                            } ?? .dictionary(fields),
                            sourceRange: decoded.range
                        )
                    }
                    return BodyTreeNode(
                        name: "Decoded value",
                        value: decoded.value,
                        sourceRange: decoded.range
                    )
                }
            }
            fallthrough
        default:
            return Self.error(index: index)
        }
    }

    private static func unwrap(
        _ value: TraceValue,
        inheritedRange: Range<Int>?
    ) -> (value: TraceValue, range: Range<Int>?, explicit: Bool) {
        if case .sourced(let range, let nested) = value {
            let unwrapped = unwrap(nested, inheritedRange: range)
            return (unwrapped.value, unwrapped.range, true)
        }
        return (value, inheritedRange, false)
    }
}
