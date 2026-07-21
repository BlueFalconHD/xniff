import Foundation

public struct CoreDataFetchOperationDecoder: CoreDataOperationDecoder {
    public let code: Int64 = 2
    public let name = "Fetch request"

    public init() {}

    public func decode(_ body: TraceValue) -> TraceValue {
        guard case .array(let envelope) = body.coreDataUnwrapped else { return body }

        // NSXPCStore archives [fetchData, optionalQueryGeneration]. The fetchData
        // element is itself the archive produced by -[NSFetchRequest encodeForXPC].
        if (envelope.count == 1 || envelope.count == 2),
           let encodedRequest = envelope.first {
            let request = CoreDataArchiveRepresentation.decode(encodedRequest)
            let generation = envelope.indices.contains(1) ? envelope[1] : nil
            return CoreDataFetchRequestSchema.decode(
                request,
                queryGeneration: generation
            )
        }

        // Accept the inner representation directly for captures that start after
        // the outer keyed archive has already been removed.
        return CoreDataFetchRequestSchema.decode(body)
    }
}

enum CoreDataFetchRequestSchema {
    static let fieldNames = [
        "Entity",
        "Encoded flags",
        "Sort descriptors",
        "Predicate",
        "Having predicate",
        "Prefetch relationship key paths",
        "Fetch offset",
        "Fetch limit",
        "Fetch batch size",
        "Properties to fetch",
        "Properties to group by",
    ]

    static func decode(
        _ value: TraceValue,
        queryGeneration: TraceValue? = nil
    ) -> TraceValue {
        let decoded = CoreDataArchiveRepresentation.decode(value)
        guard case .array(let values) = decoded.coreDataUnwrapped,
              values.count >= fieldNames.count else {
            var fields = [TraceField(name: "Encoded request", value: decoded)]
            if let queryGeneration {
                fields.append(TraceField(name: "Query generation", value: queryGeneration))
            }
            return .object(type: "Core Data fetch request", fields: fields)
        }

        var fields = fieldNames.enumerated().map { index, name in
            TraceField(name: name, value: values[index])
        }
        if values.count > fieldNames.count {
            for index in fieldNames.count..<values.count {
                fields.append(TraceField(name: "Additional request field \(index)", value: values[index]))
            }
        }
        if let queryGeneration {
            fields.append(TraceField(name: "Query generation", value: queryGeneration))
        }

        return decoded.replacingOutermostSourcedValue(with: .object(
            type: "Core Data fetch request",
            fields: fields
        ))
    }
}
