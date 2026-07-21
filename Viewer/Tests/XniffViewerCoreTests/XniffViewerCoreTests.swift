import Foundation
import Testing
@testable import XniffViewerCore

private let diagnosticSerialization = Data(hex: """
423713420500000000f000003800000002000000
6b696e64000000000090000011000000786e6966662d646961676e6f7374696300
0000007069640000300000af3e010000000000
""")

@Test func decodesPrivateXPCSerialization() throws {
    let value = try XPCSerializationDecoder.decode(diagnosticSerialization)
    #expect(value.stringValue(at: "kind") == "xniff-diagnostic")
    #expect(value.integerValue(at: "pid") == 81_583)
}

@Test func decodesNSKeyedArchiverWithoutApplicationClasses() throws {
    let archive = try NSKeyedArchiver.archivedData(
        withRootObject: ["hello": "world", "items": [1, 2, 3]],
        requiringSecureCoding: false
    )
    let value = try KeyedArchiveDecoder.decode(archive)
    #expect(value.recursiveStrings.contains("world"))
    #expect(value.recursiveStrings.contains("hello"))
}

@Test func structurallyDecodesUnknownArchivedClasses() throws {
    let archive = try NSKeyedArchiver.archivedData(
        withRootObject: MysteryArchiveObject(payload: "private-value"),
        requiringSecureCoding: false
    )
    let value = try KeyedArchiveDecoder.decode(archive)
    #expect(value.recursiveStrings.contains("private-value"))
    #expect(value.recursiveStrings.contains(where: { $0.contains("MysteryArchiveObject") }))
}

@Test func normalizesArchivedNSNull() throws {
    let archive = try NSKeyedArchiver.archivedData(
        withRootObject: NSNull(),
        requiringSecureCoding: false
    )
    let value = try KeyedArchiveDecoder.decode(archive)
    #expect(value.summary == "null")
}

@Test func indexesAndPairsXPCRecords() throws {
    let callID: UInt64 = 77
    let request = makeRecord(direction: 0, sequence: 1, callID: callID, reply: false)
    let response = makeRecord(direction: 1, sequence: 2, callID: callID, reply: true)
    var file = Data()
    file.appendLE(UInt32(0x584e4246))
    file.appendLE(UInt16(2))
    file.appendLE(UInt16(0))
    file.append(request)
    file.append(response)

    let document = try XniffTraceParser.parse(data: file)
    #expect(document.events.count == 2)
    #expect(document.events[0].role == .request)
    #expect(document.events[1].role == .response)
    #expect(document.events[0].callID == document.events[1].callID)
    #expect(document.calls.count == 1)
    #expect(document.calls[0].request?.id == document.events[0].id)
    #expect(document.calls[0].response?.id == document.events[1].id)

    let payload = try #require(document.events[0].payloads.first)
    let decoded = EmbeddedPayloadDecoder.decode(document.data(for: payload), format: payload.format)
    #expect(decoded.stringValue(at: "kind") == "xniff-diagnostic")
}

@Test func pairsInternalAsyncReplyDeliveryWithoutDuplicatingTheRequestBody() throws {
    let callID: UInt64 = 78
    var file = Data()
    file.appendLE(UInt32(0x584e4246))
    file.appendLE(UInt16(2))
    file.appendLE(UInt16(0))
    file.append(makeRecord(direction: 0, sequence: 1, callID: callID, reply: false, function: 4))
    file.append(makeRecord(direction: 1, sequence: 2, callID: callID, reply: true, function: 4))

    let document = try XniffTraceParser.parse(data: file)
    let call = try #require(document.calls.first)

    #expect(document.calls.count == 1)
    #expect(call.functionName == "xpc_connection_send_message_with_reply")
    #expect(call.request?.payloads.map(\.kind) == [.message])
    #expect(call.response?.payloads.map(\.kind) == [.reply])
}

@Test func acceptsAnEmptyCapture() throws {
    var file = Data()
    file.appendLE(UInt32(0x584e4246))
    file.appendLE(UInt16(2))
    file.appendLE(UInt16(0))

    let document = try XniffTraceParser.parse(data: file)
    #expect(document.events.isEmpty)
}

@Test func retainsDataWhileDecodingItsPropertyList() throws {
    let plist = try PropertyListSerialization.data(
        fromPropertyList: ["hello": "world"],
        format: .binary,
        options: 0
    )
    let value = EmbeddedPayloadDecoder.expandEmbeddedData(
        .sourced(range: 0x120..<0x200, value: .data(plist, interpretation: nil))
    )
    guard case .sourced(_, let wrapped) = value,
          case .data(let bytes, let interpretation) = wrapped else {
        Issue.record("Expected a sourced Data value")
        return
    }
    #expect(bytes == plist)
    #expect(interpretation?.summary.contains("Binary property list v0 at 0x128") == true)
    #expect(interpretation?.recursiveStrings.contains("world") == true)
}

@Test func decodesInlineBPlist17Dictionary() throws {
    let data = Data(hex: """
        62706C6973743137
        D01E00000000000000
        7668656C6C6F00
        76776F726C6400
        """)
    let value = try BPlist17Decoder.decode(data, sourceOffset: 0x400)
    #expect(value.recursiveStrings.contains("hello"))
    #expect(value.recursiveStrings.contains("world"))
}

@Test func doesNotMistakeArbitraryBPlistForFoundationNSXPC() throws {
    let data = Data(hex: """
        62706C6973743137
        D01E00000000000000
        7668656C6C6F00
        76776F726C6400
        """)
    let expanded = EmbeddedPayloadDecoder.expandEmbeddedData(.dictionary([
        TraceField(name: "f", value: .unsigned(33)),
        TraceField(name: "proxynum", value: .unsigned(1)),
        TraceField(name: "replysig", value: .string(#"v16@?0@"NSString"8"#)),
        TraceField(name: "sequence", value: .unsigned(7)),
        TraceField(name: "root", value: .data(data, interpretation: nil)),
    ]))
    #expect(FoundationXPCEnvelopeDecoder.decode(expanded) == nil)
}

@Test func inspectorRegistryOrdersAndChainsApplicableLayers() throws {
    let registry = BodyInspectorRegistry(inspectors: [
        TestInspector(id: "raw", parent: nil, priority: 0, output: .string("wire")),
        TestInspector(id: "middle", parent: "raw", priority: 10, output: .string("decoded")),
        TestInspector(id: "highest", parent: "middle", priority: 20, output: .string("semantic")),
        TestInspector(id: "unrelated", parent: "missing", priority: 1_000, output: .string("bad")),
    ])
    let inspections = registry.inspections(for: .null, data: Data())
    #expect(inspections.map(\.id) == ["highest", "middle", "raw"])
    #expect(inspections.first?.tree?.summary == "semantic")
}

@Test func standardInspectorsTreatHexAsTheRawXPCParent() throws {
    let bytes = Data([0x42, 0x13, 0x37, 0x42])
    let inspections = BodyInspectorRegistry.standard.inspections(for: .null, data: bytes)
    let raw = try #require(inspections.first { $0.id == StandardBodyInspectorID.rawXPC })
    let hex = try #require(inspections.first { $0.id == StandardBodyInspectorID.hex })

    #expect(raw.parentID == hex.id)
    guard case .bytes(let inspectedBytes) = hex.content else {
        Issue.record("Expected Hex to expose byte content")
        return
    }
    #expect(inspectedBytes == bytes)
}

@Test func rendersCopiedTreesAsReadableStructuredText() {
    let value = TraceValue.object(type: "Message", fields: [
        TraceField(name: "operation name", value: .string("fetch")),
        TraceField(name: "items", value: .array([.signed(1), .bool(true)])),
    ])

    #expect(TraceValueTextRenderer.render(value, rootName: "body") == """
        body: Message {
          "operation name": "fetch"
          items: [
            1
            true
          ]
        }
        """)
}

@Test func supportsRegisteringAdditionalCoreDataOperations() {
    let registry = CoreDataOperationRegistry(decoders: [TestCoreDataOperationDecoder()])
    let operation = registry.decode(.string("wire value"), code: 99)

    #expect(operation.name == "Custom operation")
    #expect(operation.body.summary == "decoded custom value")
}

@Test func decodesExternalTraceWhenProvided() async throws {
    guard let path = ProcessInfo.processInfo.environment["XNIFF_TEST_TRACE"] else { return }
    let clock = ContinuousClock()
    let started = clock.now
    let document = try XniffTraceParser.parse(url: URL(fileURLWithPath: path))
    let inputs = document.events.flatMap { event in
        event.payloads.map { payload in
            TracePayloadInput(slice: payload, data: document.data(for: payload))
        }
    }
    let decoded = await TracePayloadDecoder.decode(inputs)
    let bplist17Count = decoded.count {
        $0.value.recursiveStrings.contains { $0.hasPrefix("Binary property list v17") }
    }
    let bplist17Errors = decoded.flatMap { $0.value.recursiveErrors }
    let foundationInspections = decoded.compactMap {
        $0.inspection(withID: StandardBodyInspectorID.foundationNSXPC)
    }
    let coreDataInspections = decoded.compactMap {
        $0.inspection(withID: StandardBodyInspectorID.coreDataXPC)
    }
    let coreDataMessages = foundationInspections.compactMap { inspection in
        inspection.tree.flatMap { CoreDataXPCMessageDecoder.decode($0) }
    }
    let archivedTypes = Set(foundationInspections.flatMap { $0.tree?.recursiveObjectTypes ?? [] }).sorted()
    var shapeCounts: [String: Int] = [:]
    var decodedIndex = 0
    for event in document.events {
        for _ in event.payloads {
            if let foundation = decoded[decodedIndex]
                .inspection(withID: StandardBodyInspectorID.foundationNSXPC),
               let foundationBody = foundation.tree,
               let message = CoreDataXPCMessageDecoder.decode(foundationBody) {
                let key = "\(event.role.rawValue) code \(message.code.map(String.init) ?? "?"): "
                    + message.logicalBody.structuralShape
                shapeCounts[key, default: 0] += 1
            }
            decodedIndex += 1
        }
    }
    print(
        "Decoded \(decoded.count) payloads from \(document.calls.count) calls, "
            + "including \(bplist17Count) bplist17 bodies in \(foundationInspections.count) Foundation inspections "
            + "and \(coreDataInspections.count) semantic Core Data inspections "
            + "with \(bplist17Errors.count) structural errors, "
            + "in \(started.duration(to: clock.now))"
    )
    print("Observed archived classes: \(archivedTypes.joined(separator: ", "))")
    for (shape, count) in shapeCounts.sorted(by: { $0.key < $1.key }) {
        print("\(count)× \(shape)")
    }
    #expect(decoded.count == inputs.count)
    #expect(document.calls.count <= document.events.count)
    #expect(bplist17Count > 0)
    #expect(!foundationInspections.isEmpty)
    #expect(!coreDataMessages.isEmpty)
}

private func makeRecord(
    direction: UInt16,
    sequence: UInt64,
    callID: UInt64,
    reply: Bool,
    function: UInt32 = 5
) -> Data {
    var fixed = Data()
    fixed.appendLE(UInt32(99))
    fixed.appendLE(UInt32(7))
    fixed.appendLE(sequence)
    fixed.appendLE(direction)
    fixed.appendLE(UInt16(3))
    fixed.appendLE(function)

    var call = Data()
    call.appendLE(UInt32(3))
    call.appendLE(UInt32(direction))
    call.appendLE(function)
    call.appendLE(UInt32(0))
    call.appendLE(UInt64(reply ? 1 : 0))
    for _ in 0..<8 { call.appendLE(UInt64(0)) }
    for _ in 0..<4 { call.appendLE(UInt32(0)) }

    var body = fixed
    body.appendSection(type: 10, payload: call)
    var callIDData = Data()
    callIDData.appendLE(callID)
    body.appendSection(type: 13, payload: callIDData)

    var serialized = Data()
    serialized.append(reply ? 2 : 1)
    serialized.append(1)
    serialized.appendLE(UInt16(0))
    serialized.appendLE(UInt32(diagnosticSerialization.count))
    serialized.appendLE(UInt32(diagnosticSerialization.count))
    serialized.append(diagnosticSerialization)
    body.appendSection(type: 7, payload: serialized)

    var record = Data()
    record.appendLE(UInt32(16 + body.count))
    record.appendLE(UInt16(2))
    record.appendLE(UInt16(1))
    record.appendLE(sequence)
    record.append(body)
    return record
}

private extension Data {
    init(hex: String) {
        self.init()
        let compact = hex.filter { !$0.isWhitespace }
        var index = compact.startIndex
        while index < compact.endIndex {
            let next = compact.index(index, offsetBy: 2)
            append(UInt8(compact[index..<next], radix: 16)!)
            index = next
        }
    }

    mutating func appendLE<T: FixedWidthInteger>(_ value: T) {
        var little = value.littleEndian
        Swift.withUnsafeBytes(of: &little) { append(contentsOf: $0) }
    }

    mutating func appendSection(type: UInt16, payload: Data) {
        appendLE(type)
        appendLE(UInt16(0))
        appendLE(UInt32(payload.count))
        append(payload)
    }
}

private struct TestInspector: TraceBodyInspector {
    let identifier: String
    let parentIdentifier: String?
    let priority: Int
    let output: TraceValue

    init(id: String, parent: String?, priority: Int, output: TraceValue) {
        identifier = id
        parentIdentifier = parent
        self.priority = priority
        self.output = output
    }

    func inspect(_ context: BodyInspectorContext) -> BodyInspection? {
        if let parentIdentifier, context.inspection(parentIdentifier) == nil { return nil }
        return BodyInspection(
            id: identifier,
            name: identifier,
            priority: priority,
            parentID: parentIdentifier,
            content: .tree(output)
        )
    }
}

private struct TestCoreDataOperationDecoder: CoreDataOperationDecoder {
    let code: Int64 = 99
    let name = "Custom operation"

    func decode(_ body: TraceValue) -> TraceValue {
        .string("decoded custom value")
    }
}

private extension TraceValue {
    var recursiveStrings: Set<String> {
        switch self {
        case .string(let value): [value]
        case .array(let values): values.reduce(into: []) { $0.formUnion($1.recursiveStrings) }
        case .dictionary(let fields):
            fields.reduce(into: Set(fields.map(\.name))) { $0.formUnion($1.value.recursiveStrings) }
        case .object(let type, let fields):
            fields.reduce(into: Set([type] + fields.map(\.name))) {
                $0.formUnion($1.value.recursiveStrings)
            }
        case .data(_, let interpretation): interpretation?.recursiveStrings ?? []
        case .sourced(_, let value): value.recursiveStrings
        default: []
        }
    }

    var recursiveErrors: [String] {
        switch self {
        case .error(let message): [message]
        case .array(let values): values.flatMap(\.recursiveErrors)
        case .dictionary(let fields), .object(_, let fields): fields.flatMap { $0.value.recursiveErrors }
        case .data(_, let interpretation): interpretation?.recursiveErrors ?? []
        case .sourced(_, let value): value.recursiveErrors
        default: []
        }
    }

    var recursiveObjectTypes: Set<String> {
        switch self {
        case .array(let values): values.reduce(into: []) { $0.formUnion($1.recursiveObjectTypes) }
        case .dictionary(let fields): fields.reduce(into: []) { $0.formUnion($1.value.recursiveObjectTypes) }
        case .object(let type, let fields):
            fields.reduce(into: Set([type])) { $0.formUnion($1.value.recursiveObjectTypes) }
        case .data(_, let interpretation): interpretation?.recursiveObjectTypes ?? []
        case .sourced(_, let value): value.recursiveObjectTypes
        default: []
        }
    }

    var structuralShape: String {
        switch unsourced {
        case .null: "null"
        case .bool: "Bool"
        case .signed: "Int"
        case .unsigned: "UInt"
        case .double: "Double"
        case .string: "String"
        case .data(let data, let interpretation):
            interpretation.map { "Data(\(data.count)) → \($0.structuralShape)" } ?? "Data(\(data.count))"
        case .array(let values):
            "Array(\(values.count)) [\(values.prefix(5).map { $0.summary }.joined(separator: ", "))]"
        case .dictionary(let fields):
            "Dictionary {\(fields.prefix(5).map(\.name).joined(separator: ", "))}"
        case .object(let type, _): type
        case .reference: "Reference"
        case .sourced: "Sourced"
        case .error: "Error"
        }
    }

    func stringValue(at key: String) -> String? {
        guard case .dictionary(let fields) = unsourced,
              case .string(let value)? = fields.first(where: { $0.name == key })?.value.unsourced else { return nil }
        return value
    }

    func integerValue(at key: String) -> Int64? {
        guard case .dictionary(let fields) = unsourced,
              let value = fields.first(where: { $0.name == key })?.value.unsourced else { return nil }
        return switch value {
        case .signed(let number): number
        case .unsigned(let number): Int64(number)
        default: nil
        }
    }

    var unsourced: TraceValue {
        if case .sourced(_, let value) = self { return value.unsourced }
        return self
    }
}

@objc(XniffViewerMysteryArchiveObject)
private final class MysteryArchiveObject: NSObject, NSCoding {
    let payload: String

    init(payload: String) {
        self.payload = payload
    }

    required init?(coder: NSCoder) {
        payload = coder.decodeObject(forKey: "payload") as? String ?? ""
    }

    func encode(with coder: NSCoder) {
        coder.encode(payload, forKey: "payload")
    }
}
