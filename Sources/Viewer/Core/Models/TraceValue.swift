import Foundation

public indirect enum TraceValue: Sendable, Equatable {
    case null
    case bool(Bool)
    case signed(Int64)
    case unsigned(UInt64)
    case double(Double)
    case string(String)
    case data(Data, interpretation: TraceValue?)
    case array([TraceValue])
    case dictionary([TraceField])
    case object(type: String, fields: [TraceField])
    case reference(Int)
    case sourced(range: Range<Int>, value: TraceValue)
    case error(String)

    public var summary: String {
        switch self {
        case .null: "null"
        case .bool(let value): value ? "true" : "false"
        case .signed(let value): String(value)
        case .unsigned(let value): String(value)
        case .double(let value): String(value)
        case .string(let value): value
        case .data(let value, _): "Data (\(value.count.formatted()) bytes)"
        case .array(let values): "Array (\(values.count.formatted()) items)"
        case .dictionary(let fields): "Dictionary (\(fields.count.formatted()) keys)"
        case .object(let type, _): type
        case .reference(let index): "reference \(index)"
        case .sourced(_, let value): value.summary
        case .error(let message): message
        }
    }
}
public struct TraceField: Sendable, Equatable, Identifiable {
    public let id: UUID
    public let name: String
    public let value: TraceValue

    public init(name: String, value: TraceValue, id: UUID = UUID()) {
        self.id = id
        self.name = name
        self.value = value
    }
}
