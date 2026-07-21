import Foundation

public struct CoreDataOperation: Sendable {
    public let code: Int64?
    public let name: String
    public let body: TraceValue

    public init(code: Int64?, name: String, body: TraceValue) {
        self.code = code
        self.name = name
        self.body = body
    }
}

public protocol CoreDataOperationDecoder: Sendable {
    var code: Int64 { get }
    var name: String { get }

    func decode(_ body: TraceValue) -> TraceValue
}

public struct CoreDataOperationRegistry: Sendable {
    public static let standard = CoreDataOperationRegistry(decoders: [
        CoreDataReplyOperationDecoder(),
        CoreDataFetchOperationDecoder(),
    ])

    private let decoders: [Int64: any CoreDataOperationDecoder]

    public init(decoders: [any CoreDataOperationDecoder]) {
        self.decoders = Dictionary(uniqueKeysWithValues: decoders.map { ($0.code, $0) })
    }

    public func decode(_ body: TraceValue, code: Int64?) -> CoreDataOperation {
        guard let code else {
            return CoreDataOperation(code: nil, name: "Message", body: body)
        }
        guard let decoder = decoders[code] else {
            return CoreDataOperation(code: code, name: "Operation \(code)", body: body)
        }
        return CoreDataOperation(code: code, name: decoder.name, body: decoder.decode(body))
    }
}

public struct CoreDataReplyOperationDecoder: CoreDataOperationDecoder {
    public let code: Int64 = 0
    public let name = "Reply"

    public init() {}

    public func decode(_ body: TraceValue) -> TraceValue {
        if case .array(let values) = body.coreDataUnwrapped,
           let declaredCount = values.first?.coreDataSignedNumber,
           declaredCount >= 0,
           declaredCount == values.count - 1 {
            return body.replacingOutermostSourcedValue(with: .object(
                type: "Core Data result set",
                fields: [TraceField(name: "Results", value: .array(Array(values.dropFirst())))]
            ))
        }

        if case .data = body.coreDataUnwrapped {
            return body.replacingOutermostSourcedValue(with: .object(
                type: "Opaque Core Data result buffer",
                fields: [TraceField(name: "Undecoded result data", value: body.coreDataUnwrapped)]
            ))
        }

        return body
    }
}

public struct CoreDataFetchOperationDecoder: CoreDataOperationDecoder {
    private struct Slot {
        let index: Int
        let name: String
        let omitWhenDefault: Bool
    }

    private static let knownSlots = [
        Slot(index: 0, name: "Entity", omitWhenDefault: false),
        Slot(index: 1, name: "Request options", omitWhenDefault: true),
        Slot(index: 2, name: "Sort descriptors", omitWhenDefault: true),
        Slot(index: 3, name: "Predicate", omitWhenDefault: true),
    ]
    private static let expectedSlotCount = 11

    public let code: Int64 = 2
    public let name = "Fetch request"

    public init() {}

    public func decode(_ body: TraceValue) -> TraceValue {
        guard case .array(let values) = body.coreDataUnwrapped,
              values.count == Self.expectedSlotCount else {
            return body
        }

        var fields = Self.knownSlots.compactMap { slot -> TraceField? in
            let value = values[slot.index]
            guard !slot.omitWhenDefault || !value.isCoreDataProtocolDefault else { return nil }
            return TraceField(name: slot.name, value: value)
        }
        let knownIndexes = Set(Self.knownSlots.map(\.index))
        for index in values.indices
        where !knownIndexes.contains(index) && !values[index].isCoreDataProtocolDefault {
            fields.append(TraceField(name: "Unidentified field \(index)", value: values[index]))
        }

        return body.replacingOutermostSourcedValue(with: .object(
            type: "Core Data fetch request",
            fields: fields
        ))
    }
}
