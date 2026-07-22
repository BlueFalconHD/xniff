import Foundation

struct CoreDataSaveRequestDecoder: CoreDataOperationDecoder {
    let code: Int64 = 3
    let name = "Save request"

    func decode(_ body: TraceValue) -> TraceValue {
        guard case .dictionary(let archivedFields) = body.coreDataUnwrapped else { return body }
        let fields = archivedFields.map { field in
            TraceField(
                name: Self.fieldNames[field.name] ?? field.name,
                value: Self.objectRows(in: field.value, key: field.name)
            )
        }
        return body.replacingOutermostSourcedValue(with: .object(type: "Core Data save request", fields: fields))
    }

    private static func objectRows(in value: TraceValue, key: String) -> TraceValue {
        guard ["inserted", "deleted", "updated", "locked"].contains(key),
              case .array(let rows) = value.coreDataUnwrapped else {
            return value
        }
        return value.replacingOutermostSourcedValue(with: .array(rows.map(decodeRow)))
    }

    private static func decodeRow(_ value: TraceValue) -> TraceValue {
        guard case .array(let fields) = value.coreDataUnwrapped, fields.count >= 3 else {
            return value
        }
        return value.replacingOutermostSourcedValue(with: .object(
            type: "Core Data saved object",
            fields: [
                TraceField(name: "Object ID", value: fields[0]),
                TraceField(name: "Version", value: fields[1]),
                TraceField(name: "No-change sentinel", value: fields[2]),
                TraceField(name: "Property values", value: .array(Array(fields.dropFirst(3)))),
            ]
        ))
    }

    private static let fieldNames = [
        "NSMetadata": "Metadata",
        "inserted": "Inserted objects",
        "deleted": "Deleted objects",
        "updated": "Updated objects",
        "locked": "Locked objects",
    ]
}
