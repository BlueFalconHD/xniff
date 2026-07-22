import Foundation

public enum TraceValueTextRenderer {
    public static func render(_ value: TraceValue, rootName: String? = nil) -> String {
        let rendered = render(value)
        guard let rootName, !rootName.isEmpty else { return rendered }
        return "\(rootName): \(rendered)"
    }

    private static func render(_ value: TraceValue) -> String {
        switch value.unsourced {
        case .null:
            return "null"
        case .bool(let value):
            return value ? "true" : "false"
        case .signed(let value):
            return String(value)
        case .unsigned(let value):
            return String(value)
        case .double(let value):
            return String(value)
        case .string(let value):
            return String(reflecting: value)
        case .data(let data, let interpretation):
            guard let interpretation else { return "Data(\(data.count) bytes)" }
            return block(
                opening: "Data(\(data.count) bytes) {",
                lines: ["decoded: \(render(interpretation))"],
                closing: "}"
            )
        case .array(let values):
            return block(
                opening: "[",
                lines: values.map(render),
                closing: "]"
            )
        case .dictionary(let fields):
            return render(fields: fields, type: nil)
        case .object(let type, let fields):
            return render(fields: fields, type: type)
        case .reference(let index):
            return "reference(\(index))"
        case .sourced(_, let nested):
            return render(nested)
        case .error(let message):
            return "error(\(String(reflecting: message)))"
        }
    }

    private static func render(fields: [TraceField], type: String?) -> String {
        block(
            opening: type.map { "\($0) {" } ?? "{",
            lines: fields.map { "\(fieldName($0.name)): \(render($0.value))" },
            closing: "}"
        )
    }

    private static func block(
        opening: String,
        lines: [String],
        closing: String
    ) -> String {
        guard !lines.isEmpty else { return opening + closing }
        let body = lines.map(indent).joined(separator: "\n")
        return "\(opening)\n\(body)\n\(closing)"
    }

    private static func indent(_ text: String) -> String {
        "  " + text.replacingOccurrences(of: "\n", with: "\n  ")
    }

    private static func fieldName(_ name: String) -> String {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "_-$"))
        if !name.isEmpty, name.unicodeScalars.allSatisfy(allowed.contains) {
            return name
        }
        return String(reflecting: name)
    }
}

private extension TraceValue {
    var unsourced: TraceValue {
        if case .sourced(_, let value) = self { return value.unsourced }
        return self
    }
}
