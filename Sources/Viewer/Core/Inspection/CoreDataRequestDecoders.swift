import Foundation

struct CoreDataEmptyRequestDecoder: CoreDataOperationDecoder {
    let code: Int64
    let name: String

    func decode(_ body: TraceValue) -> TraceValue {
        guard case .null = body.coreDataUnwrapped else {
            return .object(type: name, fields: [TraceField(name: "Body", value: body)])
        }
        return .object(type: name, fields: [])
    }
}

struct CoreDataPermanentIDRequestDecoder: CoreDataOperationDecoder {
    let code: Int64 = 4
    let name = "Obtain permanent IDs"

    func decode(_ body: TraceValue) -> TraceValue {
        guard case .dictionary(let entityCounts) = body.coreDataUnwrapped else { return body }
        return body.replacingOutermostSourcedValue(with: .object(
            type: name,
            fields: [TraceField(name: "Entity counts", value: .dictionary(entityCounts))]
        ))
    }
}

struct CoreDataObjectFaultRequestDecoder: CoreDataOperationDecoder {
    let code: Int64 = 5
    let name = "Object fault request"

    func decode(_ body: TraceValue) -> TraceValue {
        guard case .array(let values) = body.coreDataUnwrapped, let objectURI = values.first else {
            return body
        }
        var fields = [TraceField(name: "Object ID URI", value: objectURI)]
        if values.indices.contains(1) {
            fields.append(TraceField(name: "Query generation", value: values[1]))
        }
        appendAdditional(values, after: 1, to: &fields)
        return body.replacingOutermostSourcedValue(with: .object(type: name, fields: fields))
    }
}

struct CoreDataRelationshipFaultRequestDecoder: CoreDataOperationDecoder {
    let code: Int64 = 6
    let name = "Relationship fault request"

    func decode(_ body: TraceValue) -> TraceValue {
        guard case .array(let values) = body.coreDataUnwrapped, let request = values.first else {
            return body
        }
        var fields: [TraceField]
        if case .dictionary(let requestFields) = request.coreDataUnwrapped {
            fields = requestFields.map {
                TraceField(name: Self.fieldNames[$0.name] ?? $0.name, value: $0.value)
            }
        } else {
            fields = [TraceField(name: "Request", value: request)]
        }
        if values.indices.contains(1) {
            fields.append(TraceField(name: "Query generation", value: values[1]))
        }
        appendAdditional(values, after: 1, to: &fields)
        return body.replacingOutermostSourcedValue(with: .object(type: name, fields: fields))
    }

    private static let fieldNames = [
        "source": "Source object ID URI",
        "relationship": "Relationship",
    ]
}

struct CoreDataCurrentChangeTokenRequestDecoder: CoreDataOperationDecoder {
    let code: Int64 = 14
    let name = "Current persistent history token"

    func decode(_ body: TraceValue) -> TraceValue {
        guard case .array(let values) = body.coreDataUnwrapped, let identifier = values.first else {
            return body
        }
        var fields = [TraceField(name: "Store identifier", value: identifier)]
        appendAdditional(values, after: 0, to: &fields)
        return body.replacingOutermostSourcedValue(with: .object(type: name, fields: fields))
    }
}

struct CoreDataArchivedObjectRequestDecoder: CoreDataOperationDecoder {
    let code: Int64
    let name: String

    func decode(_ body: TraceValue) -> TraceValue {
        guard case .object(_, let archivedFields) = body.coreDataUnwrapped else { return body }
        let fields = archivedFields.map {
            TraceField(name: Self.fieldNames[$0.name] ?? $0.name, value: $0.value)
        }
        return body.replacingOutermostSourcedValue(with: .object(type: name, fields: fields))
    }

    private static let fieldNames = [
        "NSQueryTokenIsSingleton": "Is singleton",
        "NSQueryTokenWhichSingleton": "Singleton kind",
        "NSQueryTokenIsCompound": "Is compound",
        "NSQueryTokenStoreIdentifier": "Store identifier",
        "NSQueryTokenGenerationIdentifier": "Generation identifier",
    ]
}

struct CoreDataTokenRequestDecoder: CoreDataOperationDecoder {
    let code: Int64
    let name: String

    func decode(_ body: TraceValue) -> TraceValue {
        guard case .object(_, let archivedFields) = body.coreDataUnwrapped else { return body }
        let fields = archivedFields.map { field in
            TraceField(
                name: Self.fieldNames[field.name] ?? field.name,
                value: decodedValue(field.value, forKey: field.name)
            )
        }
        return body.replacingOutermostSourcedValue(with: .object(type: name, fields: fields))
    }

    private func decodedValue(_ value: TraceValue, forKey key: String) -> TraceValue {
        let decoded = CoreDataArchiveRepresentation.decode(value)
        if key == "fetch" {
            return CoreDataFetchRequestSchema.decode(decoded)
        }
        return decoded
    }

    private static let fieldNames = [
        "entityName": "Entity",
        "objectsToInsert": "Objects to insert",
        "inputStream": "Input stream",
        "resultType": "Result type",
        "secure": "Secure",
        "predicate": "Predicate",
        "columnsToUpdate": "Properties to update",
        "nullValueCount": "Null value count",
        "includeSubEntities": "Includes subentities",
        "fetch": "Fetch request",
        "token": "History token",
        "date": "Date",
        "delete": "Delete",
        "transactionFromToken": "Transaction for token",
        "fetchLimit": "Fetch limit",
        "fetchOffset": "Fetch offset",
        "fetchBatchSize": "Fetch batch size",
        "percentageOfDB": "Store percentage threshold",
    ]
}

private func appendAdditional(
    _ values: [TraceValue],
    after lastKnownIndex: Int,
    to fields: inout [TraceField]
) {
    guard values.count > lastKnownIndex + 1 else { return }
    for index in (lastKnownIndex + 1)..<values.count {
        fields.append(TraceField(name: "Additional field \(index)", value: values[index]))
    }
}
