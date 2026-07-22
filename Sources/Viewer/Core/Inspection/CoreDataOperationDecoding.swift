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
        CoreDataEmptyRequestDecoder(code: 1, name: "Metadata request"),
        CoreDataFetchOperationDecoder(),
        CoreDataSaveRequestDecoder(),
        CoreDataPermanentIDRequestDecoder(),
        CoreDataObjectFaultRequestDecoder(),
        CoreDataRelationshipFaultRequestDecoder(),
        CoreDataEmptyRequestDecoder(code: 7, name: "Remote change notification request"),
        CoreDataEmptyRequestDecoder(code: 9, name: "Current query generation request"),
        CoreDataArchivedObjectRequestDecoder(code: 10, name: "Release query generation"),
        CoreDataArchivedObjectRequestDecoder(code: 11, name: "Reopen query generation"),
        CoreDataTokenRequestDecoder(code: 12, name: "Batch delete request"),
        CoreDataTokenRequestDecoder(code: 13, name: "Persistent history request"),
        CoreDataCurrentChangeTokenRequestDecoder(),
        CoreDataTokenRequestDecoder(code: 15, name: "Batch update request"),
        CoreDataTokenRequestDecoder(code: 16, name: "Batch insert request"),
        CoreDataEmptyRequestDecoder(code: 17, name: "Active query generations request"),
    ])

    private let decoders: [Int64: any CoreDataOperationDecoder]

    public init(decoders: [any CoreDataOperationDecoder]) {
        self.decoders = Dictionary(uniqueKeysWithValues: decoders.map { ($0.code, $0) })
    }

    public func decode(_ body: TraceValue, code: Int64?) -> CoreDataOperation {
        decode(Optional(body), code: code)
    }

    public func decode(_ body: TraceValue?, code: Int64?) -> CoreDataOperation {
        decode(body, code: code, request: nil)
    }

    func decode(
        _ body: TraceValue?,
        code: Int64?,
        request: CoreDataXPCMessage?
    ) -> CoreDataOperation {
        guard let code else {
            return CoreDataOperation(code: nil, name: "Message", body: body ?? .null)
        }

        // The server uses request code 2 for fetches and reply code 2 for failures.
        // A fetch always has an archived body; an error response does not.
        if code == 2, body == nil {
            return CoreDataOperation(code: code, name: "Error response", body: .null)
        }

        // Reply code 8 means that processing produced neither a result nor an error.
        if code == 8 {
            return CoreDataOperation(code: code, name: "Empty response", body: body ?? .null)
        }

        if code == 0,
           let response = NSXPCStoreResponseDecoder.decode(
               body ?? .null,
               for: request
           ) {
            return response
        }

        guard let decoder = decoders[code] else {
            return CoreDataOperation(code: code, name: "Operation \(code)", body: body ?? .null)
        }
        return CoreDataOperation(
            code: code,
            name: decoder.name,
            body: decoder.decode(body ?? .null)
        )
    }
}
