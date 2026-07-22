import Foundation
import Testing
@testable import XniffViewerCore

@Test func decodesSwiftXPCCodableContainerGraph() throws {
    var body = Data()
    body.appendMetadata(0x0B)
    body.append(0x0F)
    body.appendLittleEndian(UInt64(41_300_000))
    body.appendReference(0)
    body.append(0x15)

    body.appendMetadata(0x0A)
    body.appendKey("createSession")
    body.appendReference(1)
    body.append(0x15)

    body.appendMetadata(0x0A)
    body.appendKey("_0")
    body.appendReference(2)
    body.append(0x15)

    body.appendMetadata(0x0A)
    body.appendKey("name")
    body.appendString("hello")
    body.appendKey("count")
    body.append(0x09)
    body.appendLittleEndian(UInt32(7))

    let decoded = try SwiftXPCCodableGraphDecoder.decode(body)
    let rendered = TraceValueTextRenderer.render(decoded)
    #expect(rendered.contains("41300000"))
    #expect(rendered.contains("createSession"))
    #expect(rendered.contains("name: \"hello\""))
    #expect(rendered.contains("count: 7"))
}

@Test func resolvesSwiftXPCOutOfLineData() throws {
    var body = Data()
    body.appendMetadata(0x0C)
    body.append(0x12)
    body.appendLittleEndian(UInt32(0))

    let decoded = try SwiftXPCCodableGraphDecoder.decode(
        body,
        outOfLineObjects: [.data(Data("payload".utf8), interpretation: nil)]
    )
    let rendered = TraceValueTextRenderer.render(decoded)
    #expect(rendered.contains("Out-of-line XPC data"))
    #expect(rendered.contains("Data(7 bytes)"))
}

@Test func resolvesUnambiguousXPCCodableObjectReference() throws {
    var body = Data()
    body.appendMetadata(0x0C)
    body.append(0x06)
    body.appendLittleEndian(UInt64(0))

    let decoded = try SwiftXPCCodableGraphDecoder.decode(
        body,
        codableObjects: [.dictionary([
            TraceField(name: "secret", value: .string("resolved")),
        ])]
    )
    let rendered = TraceValueTextRenderer.render(decoded)
    #expect(rendered.contains("XPCCodableObject reference"))
    #expect(rendered.contains("secret: \"resolved\""))
}

@Test func exposesSwiftXPCCodableAsAStandardInspector() throws {
    let body = Data([0x13, 0x0B, 0x01, 0x14, 0, 0, 0, 0, 0x15, 0x13, 0x0A])
    let raw = TraceValue.dictionary([
        TraceField(name: "_CodableBody", value: .data(body, interpretation: nil)),
        TraceField(name: "_CodableOutOfLine", value: .array([])),
        TraceField(name: "_CodableOutOfLine4CodableObject", value: .array([])),
        TraceField(name: "_CodableCoderVersion", value: .signed(1)),
        TraceField(name: "_CodableIsSync", value: .bool(false)),
    ])

    let inspections = BodyInspectorRegistry.standard.inspections(for: raw, data: Data())
    let inspection = try #require(inspections.first {
        $0.id == StandardBodyInspectorID.swiftXPCCodable
    })
    #expect(inspection.parentID == StandardBodyInspectorID.rawXPC)
    #expect(inspection.tree?.summary == "Array (2 items)")
    #expect(inspection.details.contains {
        $0.label == "Delivery" && $0.value == "Asynchronous"
    })
}

@Test func decodesExternalSwiftXPCTraceWhenProvided() async throws {
    guard let path = ProcessInfo.processInfo.environment["XNIFF_TEST_SWIFT_XPC_TRACE"] else { return }
    let document = try XniffTraceParser.parse(url: URL(fileURLWithPath: path))
    let inputs = document.events.flatMap { event in
        event.payloads.map { payload in
            TracePayloadInput(slice: payload, data: document.data(for: payload))
        }
    }
    let decoded = await TracePayloadDecoder.decode(inputs)
    let inspections = decoded.compactMap {
        $0.inspection(withID: StandardBodyInspectorID.swiftXPCCodable)
    }
    let errors = inspections.flatMap { inspection in
        inspection.details.filter { $0.label == "Decode error" }.map(\.value)
    }
    print("Decoded \(inspections.count) Swift XPC Codable payloads with \(errors.count) errors")
    #expect(!inspections.isEmpty)
    #expect(errors.isEmpty)
}

private extension Data {
    mutating func appendLittleEndian<T: FixedWidthInteger>(_ value: T) {
        var littleEndian = value.littleEndian
        Swift.withUnsafeBytes(of: &littleEndian) { append(contentsOf: $0) }
    }

    mutating func appendMetadata(_ value: UInt8) {
        append(0x13)
        append(value)
    }

    mutating func appendReference(_ identifier: UInt32) {
        append(0x14)
        appendLittleEndian(identifier)
    }

    mutating func appendKey(_ value: String) {
        append(0x11)
        appendGraphString(value)
    }

    mutating func appendString(_ value: String) {
        append(0x03)
        appendGraphString(value)
    }

    mutating func appendGraphString(_ value: String) {
        let bytes = Data(value.utf8)
        appendLittleEndian(UInt64(bytes.count))
        append(bytes)
        append(0)
    }
}
