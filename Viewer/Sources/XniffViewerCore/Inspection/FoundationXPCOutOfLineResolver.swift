import Foundation

enum FoundationXPCOutOfLineResolver {
    static func resolve(_ value: TraceValue, objects: [TraceValue]) -> TraceValue {
        switch value {
        case .sourced(let range, let nested):
            return .sourced(range: range, value: resolve(nested, objects: objects))
        case .array(let values):
            return .array(values.map { resolve($0, objects: objects) })
        case .dictionary(let fields):
            return .dictionary(fields.map { field in
                TraceField(name: field.name, value: resolve(field.value, objects: objects), id: field.id)
            })
        case .object(let type, let fields):
            // NSXPCDecoder treats $xpc as an index into the envelope's `ool` array.
            guard let reference = fields.foundationValue(named: "$xpc")?.foundationUnsigned else {
                return .object(type: type, fields: fields.map { field in
                    TraceField(name: field.name, value: resolve(field.value, objects: objects), id: field.id)
                })
            }
            let resolved: TraceValue
            if reference <= UInt64(Int.max), objects.indices.contains(Int(reference)) {
                resolved = objects[Int(reference)]
            } else {
                resolved = .error("Out-of-line XPC object index \(reference) is out of range")
            }
            var resolvedFields = fields.filter { $0.name != "$xpc" }.map { field in
                TraceField(name: field.name, value: resolve(field.value, objects: objects), id: field.id)
            }
            resolvedFields.append(TraceField(name: "Out-of-line index", value: .unsigned(reference)))
            resolvedFields.append(TraceField(name: "Out-of-line value", value: resolved))
            return .object(type: type, fields: resolvedFields)
        case .data(let bytes, let interpretation):
            return .data(bytes, interpretation: interpretation.map { resolve($0, objects: objects) })
        default:
            return value
        }
    }
}
