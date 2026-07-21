import Foundation

public struct CoreDataReplyOperationDecoder: CoreDataOperationDecoder {
    public let code: Int64 = 0
    public let name = "Success response"

    public init() {}

    public func decode(_ body: TraceValue) -> TraceValue {
        decode(body, entityName: nil)
    }

    func decode(_ body: TraceValue, entityName: String?) -> TraceValue {
        body.replacingOutermostSourcedValue(with: .object(
            type: "Core Data success response",
            fields: [
                TraceField(
                    name: "Result",
                    value: CoreDataResultBufferDecoder.annotate(
                        in: body.coreDataUnwrapped,
                        entityName: entityName
                    )
                )
            ]
        ))
    }
}

enum CoreDataResultBufferDecoder {
    static func annotate(in value: TraceValue, entityName: String? = nil) -> TraceValue {
        switch value {
        case .data(let data, let interpretation):
            let annotatedInterpretation = interpretation.map {
                annotate(in: $0, entityName: entityName)
            } ?? decode(data, entityName: entityName)
            return .data(data, interpretation: annotatedInterpretation)
        case .array(let values):
            return .array(values.map { annotate(in: $0, entityName: entityName) })
        case .dictionary(let fields):
            return .dictionary(fields.map { annotate($0, entityName: entityName) })
        case .object(let type, let fields):
            return .object(type: type, fields: fields.map { annotate($0, entityName: entityName) })
        case .sourced(let range, let nested):
            return .sourced(range: range, value: annotate(in: nested, entityName: entityName))
        default:
            return value
        }
    }

    static func decode(_ data: Data, entityName: String? = nil) -> TraceValue? {
        guard data.count >= 20,
              data.coreDataUInt64(at: 0) == 1,
              data.coreDataUInt64(at: 8) == Self.marker,
              let rowCount = data.coreDataUInt32(at: 16) else {
            return nil
        }

        var fields = [
            TraceField(name: "Version", value: .unsigned(1)),
            TraceField(name: "Row count", value: .unsigned(UInt64(rowCount))),
        ]
        guard rowCount > 0 else {
            fields.append(TraceField(name: "Encoding", value: .string("Empty result")))
            return .object(type: "Core Data result buffer", fields: fields)
        }

        if let entityName {
            fields.append(TraceField(name: "Entity", value: .string(entityName)))
        }

        if data.count >= 128,
           data.coreDataUInt64(at: 24) == Self.marker,
           let structuredFields = CoreDataStructuredResultDecoder.decode(
               data,
               expectedCount: rowCount
           ) {
            fields.append(contentsOf: structuredFields)
            fields.append(TraceField(
                name: "Schema requirement",
                value: .string(
                    "Property boundaries and types come from the entity model and are not transmitted"
                )
            ))
            return .object(type: "Core Data result buffer", fields: fields)
        }

        if data.count >= 32,
           let payloadLength = data.coreDataUInt64(at: 24),
           payloadLength == UInt64(data.count - 32) {
            let payload = data.subdata(in: 32..<data.count)
            fields.append(TraceField(name: "Encoding", value: .string("Packed dictionary rows")))
            fields.append(TraceField(name: "Payload length", value: .unsigned(payloadLength)))
            if let packedRows = decodePackedRows(payload, expectedCount: rowCount) {
                fields.append(contentsOf: packedRows)
            } else {
                fields.append(TraceField(name: "Encoded rows", value: .data(payload, interpretation: nil)))
            }
            return .object(type: "Core Data result buffer", fields: fields)
        }

        return nil
    }

    static let marker: UInt64 = 0xABCDEFAB

    private static func decodePackedRows(
        _ payload: Data,
        expectedCount: UInt32
    ) -> [TraceField]? {
        guard payload.count >= 8,
              payload.coreDataUInt32(at: 0) == expectedCount,
              let sizeTableOffsetValue = payload.coreDataUInt32(at: 4) else {
            return nil
        }

        let rowCount = Int(expectedCount)
        let sizeTableOffset = Int(sizeTableOffsetValue)
        guard sizeTableOffset >= 8,
              rowCount <= (payload.count - sizeTableOffset) / 4 else {
            return nil
        }

        var sizes: [UInt32] = []
        sizes.reserveCapacity(rowCount)
        for index in 0..<rowCount {
            guard let size = payload.coreDataUInt32(at: sizeTableOffset + 4 * index) else { return nil }
            sizes.append(size)
        }

        var cursor = 8
        var rows: [TraceValue] = []
        rows.reserveCapacity(rowCount)
        for (index, sizeValue) in sizes.enumerated() {
            cursor = (cursor + 7) & ~7
            let size = Int(sizeValue)
            guard size <= sizeTableOffset - cursor else { return nil }
            let bytes = payload.subdata(in: cursor..<(cursor + size))
            rows.append(.object(type: "Row \(index)", fields: [
                TraceField(name: "Length", value: .unsigned(UInt64(sizeValue))),
                TraceField(name: "Encoded values", value: .data(bytes, interpretation: nil)),
            ]))
            cursor += size
        }

        return [
            TraceField(name: "Packed row count", value: .unsigned(UInt64(expectedCount))),
            TraceField(name: "Row sizes", value: .array(sizes.map { .unsigned(UInt64($0)) })),
            TraceField(name: "Rows", value: .array(rows)),
        ]
    }
}

private extension CoreDataResultBufferDecoder {
    static func annotate(_ field: TraceField, entityName: String?) -> TraceField {
        TraceField(
            name: field.name,
            value: annotate(in: field.value, entityName: entityName),
            id: field.id
        )
    }
}

extension Data {
    func coreDataUInt32(at offset: Int) -> UInt32? {
        guard offset >= 0, count - offset >= 4 else { return nil }
        return (0..<4).reduce(into: UInt32(0)) { result, byteOffset in
            result |= UInt32(self[index(startIndex, offsetBy: offset + byteOffset)]) << (8 * byteOffset)
        }
    }

    func coreDataUInt64(at offset: Int) -> UInt64? {
        guard offset >= 0, count - offset >= 8 else { return nil }
        return (0..<8).reduce(into: UInt64(0)) { result, byteOffset in
            result |= UInt64(self[index(startIndex, offsetBy: offset + byteOffset)]) << (8 * byteOffset)
        }
    }

    func coreDataInt(at offset: Int) -> Int? {
        guard let value = coreDataUInt64(at: offset), value <= UInt64(Int.max) else { return nil }
        return Int(value)
    }
}
