import Foundation

public enum FoundationXPCInvocationKind: String, Sendable {
    case request
    case reply

    public var label: String { rawValue.capitalized }
}

public struct FoundationXPCArgument: Sendable {
    public let index: Int
    public let type: ObjectiveCTypeDescriptor?
    public let value: TraceValue

    public var label: String {
        type.map { "Argument \(index) — \($0.displayName)" } ?? "Argument \(index)"
    }

    var semanticValue: TraceValue {
        .object(type: label, fields: [
            TraceField(name: "Encoding", value: type.map { .string($0.encoding) } ?? .string("Unavailable")),
            TraceField(name: "Value", value: value),
        ])
    }
}

public struct FoundationXPCInvocation: Sendable {
    public let kind: FoundationXPCInvocationKind
    public let selector: String?
    public let signatureEncoding: String
    public let methodSignature: ObjectiveCMethodSignature?
    public let arguments: [FoundationXPCArgument]
    public let validationIssues: [String]

    public var argumentValues: TraceValue { .array(arguments.map(\.value)) }

    public var semanticBody: TraceValue {
        var fields: [TraceField] = []
        if let selector {
            fields.append(TraceField(name: "Selector", value: .string(selector)))
        }
        fields.append(TraceField(name: "Signature", value: .string(signatureEncoding)))
        if let methodSignature {
            fields.append(TraceField(name: "Return type", value: .string(methodSignature.returnType.displayName)))
        }
        fields.append(TraceField(name: "Arguments", value: .array(arguments.map(\.semanticValue))))
        return .object(type: "NSXPC \(kind.rawValue)", fields: fields)
    }

    init?(decodedRoot: TraceValue) {
        // NSXPCEncoder writes [selector-or-null, type string, arguments]. A null
        // selector marks replies; requests carry their selector as an ASCII string.
        guard case .array(let fields) = decodedRoot.foundationUnwrapped,
              fields.count >= 3,
              let signatureEncoding = fields[1].foundationString,
              case .array(let values) = fields[2].foundationUnwrapped else {
            return nil
        }

        if let selector = fields[0].foundationString {
            kind = .request
            self.selector = selector
        } else if fields[0].foundationIsNull {
            kind = .reply
            selector = nil
        } else {
            return nil
        }

        self.signatureEncoding = signatureEncoding
        let signature = ObjectiveCMethodSignature.parse(signatureEncoding)
        methodSignature = signature
        let wireTypes = signature?.wireArguments(for: kind) ?? []
        arguments = values.enumerated().map { index, value in
            FoundationXPCArgument(
                index: index,
                type: wireTypes.indices.contains(index) ? wireTypes[index].type : nil,
                value: value
            )
        }

        var issues: [String] = []
        if fields.count > 3 {
            issues.append("Invocation metadata contains \(fields.count - 3) unexpected trailing value(s)")
        }
        if signature == nil {
            issues.append("Objective-C method signature is malformed")
        } else if wireTypes.count != values.count {
            issues.append(
                "Signature describes \(wireTypes.count) wire argument(s), but the archive contains \(values.count)"
            )
        }
        if kind == .request, let signature {
            if signature.arguments.count < 2 {
                issues.append("Request signature omits the implicit self and selector arguments")
            } else {
                if case .object = signature.arguments[0].type.kind {
                    // Expected implicit self argument.
                } else {
                    issues.append("Request signature has an invalid implicit self argument")
                }
                if signature.arguments[1].type.kind != .selector {
                    issues.append("Request signature has an invalid implicit selector argument")
                }
            }
        }
        if kind == .reply, let signature {
            if signature.returnType.kind != .void {
                issues.append("Reply signature has a non-void return type")
            }
            if signature.arguments.first?.type.isBlock != true {
                issues.append("Reply signature does not begin with the implicit block argument")
            }
        }
        validationIssues = issues
    }
}

extension TraceValue {
    var foundationUnwrapped: TraceValue {
        if case .sourced(_, let nested) = self { return nested.foundationUnwrapped }
        return self
    }

    var foundationString: String? {
        if case .string(let value) = foundationUnwrapped { return value }
        return nil
    }

    var foundationUnsigned: UInt64? {
        switch foundationUnwrapped {
        case .unsigned(let value): value
        case .signed(let value) where value >= 0: UInt64(value)
        default: nil
        }
    }

    var foundationArray: [TraceValue]? {
        if case .array(let values) = foundationUnwrapped { return values }
        return nil
    }

    var foundationIsNull: Bool {
        if case .null = foundationUnwrapped { return true }
        return false
    }
}

extension [TraceField] {
    func foundationValue(named name: String) -> TraceValue? {
        first(where: { $0.name == name })?.value
    }
}
