import Foundation
import Testing
@testable import XniffViewerCore

@Test func decodesObservedCoreDataFetchEnvelopeAndContext() throws {
    let body = try observedFetchBody(entity: "CoreUser", queryGeneration: "generation-7")
    let message = coreDataMessage(code: 2, body: body, fields: [
        TraceField(name: "NSCoreDataXPCMessageToken", value: .string("store-token")),
        TraceField(name: "NSCoreDataXPCMessageContextName", value: .string("worker")),
        TraceField(name: "NSCoreDataXPCMessageContextTransactionAuthor", value: .string("diagnostics")),
        TraceField(name: "NSCoreDataXPCMessageProcessName", value: .string("screentimediagnose")),
        TraceField(name: "NSCoreDataXPCMessageContextAllowAncillary", value: .bool(true)),
    ])

    let decoded = try #require(CoreDataXPCMessageDecoder.decode(.array([message, .null])))
    #expect(decoded.code == 2)
    #expect(decoded.operationName == "Fetch request")
    #expect(decoded.logicalBody.summary == "Core Data fetch request")
    #expect(decoded.logicalBody.coreDataTestStrings.contains("CoreUser"))
    #expect(decoded.logicalBody.coreDataTestStrings.contains("Encoded flags"))
    #expect(decoded.logicalBody.coreDataTestStrings.contains("Having predicate"))
    #expect(decoded.logicalBody.coreDataTestStrings.contains("Query generation"))
    #expect(decoded.token == "store-token")
    #expect(decoded.contextName == "worker")
    #expect(decoded.transactionAuthor == "diagnostics")
    #expect(decoded.processName == "screentimediagnose")
    #expect(decoded.allowsAncillaryEntities)
}

@Test func distinguishesFetchRequestsFromReplyStatusCodes() throws {
    let errorData = try archivedCoreDataValue(NSError(
        domain: "NSCocoaErrorDomain",
        code: 134060,
        userInfo: [NSLocalizedDescriptionKey: "The persistent store rejected the request"]
    ))
    let errorReply = foundationReply(arguments: [coreDataMessage(code: 2), errorData])
    let error = try #require(CoreDataXPCMessageDecoder.decode(errorReply))
    let empty = try #require(CoreDataXPCMessageDecoder.decode(coreDataMessage(code: 8)))

    #expect(error.operationName == "Error response")
    #expect(error.logicalBody.coreDataTestStrings.contains("NSCocoaErrorDomain"))
    #expect(error.logicalBody.coreDataTestStrings.contains("The persistent store rejected the request"))
    #expect(empty.operationName == "Empty response")
}

@Test func mapsEveryObservedCoreDataRequestCode() {
    let expected = [
        1: "Metadata request",
        3: "Save request",
        4: "Obtain permanent IDs",
        5: "Object fault request",
        6: "Relationship fault request",
        7: "Remote change notification request",
        9: "Current query generation request",
        10: "Release query generation",
        11: "Reopen query generation",
        12: "Batch delete request",
        13: "Persistent history request",
        14: "Current persistent history token",
        15: "Batch update request",
        16: "Batch insert request",
        17: "Active query generations request",
    ]

    for (code, name) in expected {
        #expect(CoreDataOperationRegistry.standard.decode(nil, code: Int64(code)).name == name)
    }
}

@Test func decodesObservedCoreDataSaveDictionaryAndRows() throws {
    let body = try archivedCoreDataValue([
        "NSMetadata": ["store": "ScreenTime"],
        "inserted": [["x-coredata://object/1", 7, "$no-change", "Alice", 42]],
        "updated": [["x-coredata://object/2", 9, "$no-change", "Bob"]],
    ])
    let decoded = try #require(CoreDataXPCMessageDecoder.decode(coreDataMessage(code: 3, body: body)))

    #expect(decoded.operationName == "Save request")
    #expect(decoded.logicalBody.coreDataTestStrings.contains("Metadata"))
    #expect(decoded.logicalBody.coreDataTestStrings.contains("Inserted objects"))
    #expect(decoded.logicalBody.coreDataTestStrings.contains("Object ID"))
    #expect(decoded.logicalBody.coreDataTestStrings.contains("Version"))
    #expect(decoded.logicalBody.coreDataTestStrings.contains("No-change sentinel"))
    #expect(decoded.logicalBody.coreDataTestStrings.contains("Property values"))
}

@Test func decodesNestedFetchArchiveInBatchDeleteToken() throws {
    let fetchData = try archivedData(observedFetchFields(entity: "Usage"))
    let token = CoreDataBatchDeleteTokenFixture(fetch: fetchData, resultType: 1, secure: true)
    let body = try archivedCoreDataValue(token)
    let decoded = try #require(CoreDataXPCMessageDecoder.decode(coreDataMessage(code: 12, body: body)))

    #expect(decoded.operationName == "Batch delete request")
    #expect(decoded.logicalBody.coreDataTestStrings.contains("Fetch request"))
    #expect(decoded.logicalBody.coreDataTestStrings.contains("Usage"))
    #expect(decoded.logicalBody.coreDataTestStrings.contains("Result type"))
    #expect(decoded.logicalBody.coreDataTestStrings.contains("Secure"))
}

@Test func parsesObservedPackedCoreDataResultBufferHeader() throws {
    var packedRows = Data()
    packedRows.appendCoreDataLE(UInt32(3))
    packedRows.appendCoreDataLE(UInt32(32))
    packedRows.append(contentsOf: [0x11, 0x22])
    packedRows.append(contentsOf: Data(repeating: 0, count: 6))
    packedRows.append(contentsOf: [0x33, 0x44, 0x55])
    packedRows.append(contentsOf: Data(repeating: 0, count: 5))
    packedRows.append(0x66)
    packedRows.append(contentsOf: Data(repeating: 0, count: 7))
    packedRows.appendCoreDataLE(UInt32(2))
    packedRows.appendCoreDataLE(UInt32(3))
    packedRows.appendCoreDataLE(UInt32(1))

    var resultBuffer = Data()
    resultBuffer.appendCoreDataLE(UInt64(1))
    resultBuffer.appendCoreDataLE(UInt64(0))
    resultBuffer.appendCoreDataLE(UInt32(3))
    resultBuffer.appendCoreDataLE(UInt32(0))
    resultBuffer.appendCoreDataLE(UInt64(packedRows.count))
    resultBuffer.append(packedRows)

    let body = try archivedCoreDataValue([resultBuffer])
    let decoded = try #require(CoreDataXPCMessageDecoder.decode(coreDataMessage(code: 0, body: body)))

    #expect(decoded.operationName == "Success response")
    #expect(decoded.logicalBody.coreDataTestStrings.contains("Core Data result buffer"))
    #expect(decoded.logicalBody.coreDataTestStrings.contains("Row count"))
    #expect(decoded.logicalBody.coreDataTestStrings.contains("Packed dictionary rows"))
    #expect(decoded.logicalBody.coreDataTestStrings.contains("Row sizes"))
    #expect(decoded.logicalBody.coreDataTestStrings.contains("Row 2"))
    #expect(decoded.logicalBody.coreDataTestStrings.contains("Encoded values"))
}

@Test func doesNotInventAResultSchemaForUnknownReplyData() throws {
    let unknown = Data(repeating: 0xAB, count: 128)
    let body = try archivedCoreDataValue([unknown])
    let decoded = try #require(CoreDataXPCMessageDecoder.decode(coreDataMessage(code: 0, body: body)))

    #expect(decoded.logicalBody.coreDataTestStrings.contains("Core Data success response"))
    #expect(!decoded.logicalBody.coreDataTestStrings.contains("Core Data result buffer"))
    #expect(!decoded.logicalBody.coreDataTestStrings.contains("Opaque Core Data result buffer"))
}

@Test func layersCoreDataInspectionAboveFoundationWithObservedDetails() throws {
    let message = coreDataMessage(
        code: 2,
        body: try observedFetchBody(entity: "CoreUser"),
        fields: [TraceField(name: "NSCoreDataXPCMessageContextName", value: .string("main"))]
    )
    let foundation = BodyInspection(
        id: StandardBodyInspectorID.foundationNSXPC,
        name: "Foundation NSXPC",
        priority: 100,
        parentID: StandardBodyInspectorID.rawXPC,
        content: .tree(.array([.string("handleRequest:reply:"), message, .null]))
    )
    let context = BodyInspectorContext(
        originalBody: .null,
        originalData: Data(),
        inspections: [StandardBodyInspectorID.foundationNSXPC: foundation]
    )

    let inspection = try #require(CoreDataXPCBodyInspector().inspect(context))
    #expect(inspection.parentID == StandardBodyInspectorID.foundationNSXPC)
    #expect(inspection.tree?.coreDataTestStrings.contains("CoreUser") == true)
    #expect(inspection.details.contains { $0.label == "Operation" && $0.value == "Fetch request" })
    #expect(inspection.details.contains { $0.label == "Context" && $0.value == "main" })
}

private func observedFetchBody(entity: String, queryGeneration: String? = nil) throws -> TraceValue {
    let fetchData = try archivedData(observedFetchFields(entity: entity))
    var envelope: [Any] = [fetchData]
    if let queryGeneration { envelope.append(queryGeneration) }
    return try archivedCoreDataValue(envelope)
}

private func observedFetchFields(entity: String) -> [Any] {
    [
        entity,
        582,
        NSNull(),
        "process == 1",
        NSNull(),
        NSNull(),
        0,
        100,
        20,
        NSNull(),
        NSNull(),
    ]
}

private func archivedData(_ root: Any) throws -> Data {
    try NSKeyedArchiver.archivedData(withRootObject: root, requiringSecureCoding: false)
}

private func archivedCoreDataValue(_ root: Any) throws -> TraceValue {
    EmbeddedPayloadDecoder.expandEmbeddedData(
        .data(try archivedData(root), interpretation: nil)
    )
}

private func coreDataMessage(
    code: Int64,
    body: TraceValue? = nil,
    fields: [TraceField] = []
) -> TraceValue {
    var messageFields = [TraceField(name: "NSCoreDataXPCMessageCode", value: .signed(code))]
    if let body {
        messageFields.append(TraceField(name: "NSCoreDataXPCMessageBody", value: body))
    }
    messageFields.append(contentsOf: fields)
    return .object(type: "NSCoreDataXPCMessage", fields: messageFields)
}

private func foundationReply(arguments: [TraceValue]) -> TraceValue {
    .object(type: "NSXPC reply", fields: [
        TraceField(name: "Signature", value: .string(#"v24@?0@"NSCoreDataXPCMessage"8@"NSData"16"#)),
        TraceField(name: "Arguments", value: .array(arguments.enumerated().map { index, value in
            .object(type: "Argument \(index)", fields: [
                TraceField(name: "Encoding", value: .string("@")),
                TraceField(name: "Value", value: value),
            ])
        })),
    ])
}

private extension TraceValue {
    var coreDataTestStrings: Set<String> {
        switch self {
        case .string(let value): [value]
        case .array(let values): values.reduce(into: []) { $0.formUnion($1.coreDataTestStrings) }
        case .dictionary(let fields):
            fields.reduce(into: Set(fields.map(\.name))) { $0.formUnion($1.value.coreDataTestStrings) }
        case .object(let type, let fields):
            fields.reduce(into: Set([type] + fields.map(\.name))) {
                $0.formUnion($1.value.coreDataTestStrings)
            }
        case .data(_, let interpretation): interpretation?.coreDataTestStrings ?? []
        case .sourced(_, let value): value.coreDataTestStrings
        default: []
        }
    }
}

private extension Data {
    mutating func appendCoreDataLE<T: FixedWidthInteger>(_ value: T) {
        var littleEndian = value.littleEndian
        Swift.withUnsafeBytes(of: &littleEndian) { append(contentsOf: $0) }
    }
}

@objc(XniffCoreDataBatchDeleteTokenFixture)
private final class CoreDataBatchDeleteTokenFixture: NSObject, NSCoding {
    let fetch: Data
    let resultType: Int
    let secure: Bool

    init(fetch: Data, resultType: Int, secure: Bool) {
        self.fetch = fetch
        self.resultType = resultType
        self.secure = secure
    }

    required init?(coder: NSCoder) {
        fetch = coder.decodeObject(forKey: "fetch") as? Data ?? Data()
        resultType = coder.decodeInteger(forKey: "resultType")
        secure = coder.decodeBool(forKey: "secure")
    }

    func encode(with coder: NSCoder) {
        coder.encode(fetch, forKey: "fetch")
        coder.encode(resultType, forKey: "resultType")
        coder.encode(secure, forKey: "secure")
    }
}
