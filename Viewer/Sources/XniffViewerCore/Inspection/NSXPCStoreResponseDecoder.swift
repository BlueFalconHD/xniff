import Foundation

enum NSXPCStoreResponseDecoder {
    static func decode(
        _ body: TraceValue,
        for request: CoreDataXPCMessage?
    ) -> CoreDataOperation? {
        guard let requestCode = request?.code else { return nil }

        switch requestCode {
        case 2:
            return CoreDataOperation(
                code: 0,
                name: "Fetch response",
                body: CoreDataReplyOperationDecoder().decode(
                    body,
                    entityName: NSXPCStoreRequestMetadata.entityName(from: request)
                )
            )
        case 5:
            return CoreDataOperation(
                code: 0,
                name: "Object fault response",
                body: NSXPCStoreObjectFaultResponseDecoder.decode(body, request: request)
            )
        default:
            return nil
        }
    }
}

enum NSXPCStoreRequestMetadata {
    static func entityName(from request: CoreDataXPCMessage?) -> String? {
        guard let request else { return nil }
        if request.code == 2,
           case .object(_, let fields) = request.logicalBody.coreDataUnwrapped {
            return fields.coreDataValue(named: "Entity")?.coreDataString
        }
        guard let objectID = objectID(from: request),
              let url = URL(string: objectID) else {
            return nil
        }
        return url.pathComponents.dropFirst().first
    }

    static func objectID(from request: CoreDataXPCMessage?) -> String? {
        guard let request else { return nil }
        return firstString(in: request.logicalBody) { $0.hasPrefix("x-coredata://") }
    }

    private static func firstString(
        in value: TraceValue,
        matching predicate: (String) -> Bool
    ) -> String? {
        switch value.coreDataUnwrapped {
        case .string(let string):
            return predicate(string) ? string : nil
        case .array(let values):
            for value in values {
                if let found = firstString(in: value, matching: predicate) { return found }
            }
            return nil
        case .dictionary(let fields), .object(_, let fields):
            for field in fields {
                if let found = firstString(in: field.value, matching: predicate) { return found }
            }
            return nil
        default:
            return nil
        }
    }
}

private enum NSXPCStoreObjectFaultResponseDecoder {
    static func decode(_ body: TraceValue, request: CoreDataXPCMessage?) -> TraceValue {
        guard case .array(let result) = body.coreDataUnwrapped,
              let status = result.first?.coreDataSignedNumber else {
            return body
        }

        var fields = [TraceField(name: "Wire status", value: .signed(status))]
        if let objectID = NSXPCStoreRequestMetadata.objectID(from: request) {
            fields.append(TraceField(name: "Object ID", value: .string(objectID)))
        }
        if let entity = NSXPCStoreRequestMetadata.entityName(from: request) {
            fields.append(TraceField(name: "Entity", value: .string(entity)))
        }

        if status == 1, result.count == 1 {
            fields.append(TraceField(name: "Result", value: .string("Object not found")))
        } else if status == 1,
                  let snapshot = result.last,
                  case .array(let values) = snapshot.coreDataUnwrapped,
                  let version = values.last {
            let propertyFields = values.dropLast().enumerated().map { index, value in
                TraceField(name: "Property slot \(index)", value: value)
            }
            fields.append(TraceField(
                name: "Property values",
                value: .object(type: "", fields: propertyFields)
            ))
            fields.append(TraceField(name: "Version", value: version))
        } else if status == 2 {
            fields.append(TraceField(
                name: "Buffered result",
                value: CoreDataResultBufferDecoder.annotate(
                    in: body.coreDataUnwrapped,
                    entityName: NSXPCStoreRequestMetadata.entityName(from: request)
                )
            ))
        } else {
            fields.append(TraceField(name: "Result", value: body.coreDataUnwrapped))
        }

        return body.replacingOutermostSourcedValue(with: .object(
            type: "Core Data object fault response",
            fields: fields
        ))
    }
}
