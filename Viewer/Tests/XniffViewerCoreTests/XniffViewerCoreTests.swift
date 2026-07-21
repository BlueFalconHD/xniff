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

    let payload = try #require(document.events[0].payloads.first)
    let decoded = EmbeddedPayloadDecoder.decode(document.data(for: payload), format: payload.format)
    #expect(decoded.stringValue(at: "kind") == "xniff-diagnostic")
}

@Test func acceptsAnEmptyCapture() throws {
    var file = Data()
    file.appendLE(UInt32(0x584e4246))
    file.appendLE(UInt16(2))
    file.appendLE(UInt16(0))

    let document = try XniffTraceParser.parse(data: file)
    #expect(document.events.isEmpty)
}

private func makeRecord(direction: UInt16, sequence: UInt64, callID: UInt64, reply: Bool) -> Data {
    var fixed = Data()
    fixed.appendLE(UInt32(99))
    fixed.appendLE(UInt32(7))
    fixed.appendLE(sequence)
    fixed.appendLE(direction)
    fixed.appendLE(UInt16(3))
    fixed.appendLE(UInt32(5))

    var call = Data()
    call.appendLE(UInt32(3))
    call.appendLE(UInt32(direction))
    call.appendLE(UInt32(5))
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
        default: []
        }
    }

    func stringValue(at key: String) -> String? {
        guard case .dictionary(let fields) = self,
              case .string(let value)? = fields.first(where: { $0.name == key })?.value else { return nil }
        return value
    }

    func integerValue(at key: String) -> Int64? {
        guard case .dictionary(let fields) = self,
              let value = fields.first(where: { $0.name == key })?.value else { return nil }
        return switch value {
        case .signed(let number): number
        case .unsigned(let number): Int64(number)
        default: nil
        }
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
