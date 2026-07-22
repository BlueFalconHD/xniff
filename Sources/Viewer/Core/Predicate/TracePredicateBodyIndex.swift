import Foundation

public enum TracePredicateBodySide: String, Sendable, Equatable {
    case request
    case response
    case event
}

public enum TracePredicateScalar: Sendable, Equatable {
    case string(String)
    case number(Decimal)
    case boolean(Bool)

    var searchableText: String {
        switch self {
        case .string(let value): value
        case .number(let value): NSDecimalNumber(decimal: value).stringValue
        case .boolean(let value): value ? "true" : "false"
        }
    }
}

public struct TracePredicateTreeEntry: Sendable, Equatable {
    public let side: TracePredicateBodySide
    public let payloadName: String
    public let inspectorID: String
    public let inspectorName: String
    public let path: String
    public let name: String
    public let type: String?
    public let value: TracePredicateScalar

    public init(
        side: TracePredicateBodySide,
        payloadName: String,
        inspectorID: String,
        inspectorName: String,
        path: String,
        name: String,
        type: String? = nil,
        value: TracePredicateScalar
    ) {
        self.side = side
        self.payloadName = payloadName
        self.inspectorID = inspectorID
        self.inspectorName = inspectorName
        self.path = path
        self.name = name
        self.type = type
        self.value = value
    }

    var combinedText: String {
        "\(side.rawValue).\(inspectorName) \(path) = \(value.searchableText)"
    }
}

public struct TracePredicateBodyIndex: Sendable, Equatable {
    public let inspectorNames: [String]
    public let entries: [TracePredicateTreeEntry]

    public init(inspectorNames: [String] = [], entries: [TracePredicateTreeEntry] = []) {
        self.inspectorNames = inspectorNames
        self.entries = entries
    }

    func values(for field: TracePredicateField) -> [TracePredicateScalar] {
        switch field {
        case .inspector:
            return inspectorNames.map(TracePredicateScalar.string)
        case .tree:
            return entries.map { .string($0.combinedText) }
        case .requestTree:
            return entries.lazy.filter { $0.side == .request }
                .map { .string($0.combinedText) }
        case .responseTree:
            return entries.lazy.filter { $0.side == .response }
                .map { .string($0.combinedText) }
        case .treePath:
            return entries.map { .string($0.path) }
        case .treeName:
            return entries.map { .string($0.name) }
        case .treeValue:
            return entries.map { .string($0.value.searchableText) }
        case .treeNumber:
            return entries.compactMap { entry in
                guard case .number = entry.value else { return nil }
                return entry.value
            }
        case .treeBoolean:
            return entries.compactMap { entry in
                guard case .boolean = entry.value else { return nil }
                return entry.value
            }
        case .treeType:
            return entries.compactMap(\.type).map(TracePredicateScalar.string)
        default:
            return []
        }
    }
}

public actor TracePredicateBodyIndexCache {
    private let capacity: Int
    private var indices: [TraceCallID: TracePredicateBodyIndex] = [:]
    private var recency: [TraceCallID] = []

    public init(capacity: Int = 128) {
        self.capacity = max(1, capacity)
    }

    public func index(
        for call: TraceCall,
        document: TraceDocument
    ) async -> TracePredicateBodyIndex {
        if let cached = indices[call.id] {
            markRecentlyUsed(call.id)
            return cached
        }
        let index = await TracePredicateBodyIndexer.index(call: call, document: document)
        indices[call.id] = index
        markRecentlyUsed(call.id)
        if indices.count > capacity {
            let evicted = recency.removeFirst()
            indices.removeValue(forKey: evicted)
        }
        return index
    }

    private func markRecentlyUsed(_ id: TraceCallID) {
        recency.removeAll { $0 == id }
        recency.append(id)
    }
}

public enum TracePredicateBodyIndexer {
    public static func index(
        call: TraceCall,
        document: TraceDocument
    ) async -> TracePredicateBodyIndex {
        var indexedPayloads: [(TracePredicateBodySide, DecodedTracePayload)] = []

        let requestPayloads: [DecodedTracePayload]
        if let request = call.request {
            requestPayloads = await decode(event: request, document: document)
            indexedPayloads.append(contentsOf: requestPayloads.map { (.request, $0) })
        } else {
            requestPayloads = []
        }

        if let response = call.response {
            let counterpart = requestPayloads.map(\.value).first {
                FoundationXPCEnvelopeDecoder.decode($0) != nil
            } ?? requestPayloads.first?.value
            let responsePayloads = await decode(
                event: response,
                document: document,
                counterpartBody: counterpart
            )
            indexedPayloads.append(contentsOf: responsePayloads.map { (.response, $0) })
        }

        if call.request == nil, call.response == nil {
            let payloads = await decode(event: call.primaryEvent, document: document)
            indexedPayloads.append(contentsOf: payloads.map { (.event, $0) })
        }

        var inspectorNames: [String] = []
        var entries: [TracePredicateTreeEntry] = []
        for (side, payload) in indexedPayloads {
            for inspection in payload.inspections {
                inspectorNames.append(inspection.name)
                inspectorNames.append(inspection.id)
                for detail in inspection.details {
                    entries.append(TracePredicateTreeEntry(
                        side: side,
                        payloadName: payload.slice.name,
                        inspectorID: inspection.id,
                        inspectorName: inspection.name,
                        path: "$details\(pathComponent(detail.label))",
                        name: detail.label,
                        value: .string(detail.value)
                    ))
                }
                if let tree = inspection.tree {
                    append(
                        tree,
                        name: "$",
                        path: "$",
                        side: side,
                        payload: payload,
                        inspection: inspection,
                        entries: &entries
                    )
                }
            }
        }

        return TracePredicateBodyIndex(
            inspectorNames: Array(Set(inspectorNames)).sorted(),
            entries: entries
        )
    }

    private static func decode(
        event: TraceEvent,
        document: TraceDocument,
        counterpartBody: TraceValue? = nil
    ) async -> [DecodedTracePayload] {
        let inputs = event.payloads.map { slice in
            TracePayloadInput(slice: slice, data: document.data(for: slice))
        }
        return await TracePayloadDecoder.decode(inputs, counterpartBody: counterpartBody)
    }

    private static func append(
        _ sourceValue: TraceValue,
        name: String,
        path: String,
        side: TracePredicateBodySide,
        payload: DecodedTracePayload,
        inspection: BodyInspection,
        entries: inout [TracePredicateTreeEntry]
    ) {
        let value = unsourced(sourceValue)
        let type: String?
        if case .object(let objectType, _) = value {
            type = objectType
        } else {
            type = nil
        }
        entries.append(TracePredicateTreeEntry(
            side: side,
            payloadName: payload.slice.name,
            inspectorID: inspection.id,
            inspectorName: inspection.name,
            path: path,
            name: name,
            type: type,
            value: scalar(value)
        ))

        switch value {
        case .array(let values):
            for (index, child) in values.enumerated() {
                append(
                    child,
                    name: "[\(index)]",
                    path: "\(path)[\(index)]",
                    side: side,
                    payload: payload,
                    inspection: inspection,
                    entries: &entries
                )
            }
        case .dictionary(let fields), .object(_, let fields):
            for field in fields {
                append(
                    field.value,
                    name: field.name,
                    path: path + pathComponent(field.name),
                    side: side,
                    payload: payload,
                    inspection: inspection,
                    entries: &entries
                )
            }
        case .data(_, let interpretation):
            if let interpretation {
                append(
                    interpretation,
                    name: "Decoded value",
                    path: "\(path).decoded",
                    side: side,
                    payload: payload,
                    inspection: inspection,
                    entries: &entries
                )
            }
        default:
            break
        }
    }

    private static func unsourced(_ value: TraceValue) -> TraceValue {
        if case .sourced(_, let nested) = value { return unsourced(nested) }
        return value
    }

    private static func scalar(_ value: TraceValue) -> TracePredicateScalar {
        switch value {
        case .bool(let value): .boolean(value)
        case .signed(let value): .number(decimal(value))
        case .unsigned(let value): .number(decimal(value))
        case .double(let value): .number(decimal(value))
        case .string(let value): .string(value)
        default: .string(value.summary)
        }
    }

    private static func decimal<T: CustomStringConvertible>(_ value: T) -> Decimal {
        Decimal(string: value.description, locale: Locale(identifier: "en_US_POSIX")) ?? 0
    }

    private static func pathComponent(_ name: String) -> String {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "_-$"))
        if !name.isEmpty, name.unicodeScalars.allSatisfy(allowed.contains) {
            return ".\(name)"
        }
        let escaped = name
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
        return "[\"\(escaped)\"]"
    }
}
