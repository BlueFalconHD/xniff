import Foundation
import Testing
@testable import XniffViewerCore

@Test func decodesEveryMachRecordSection() throws {
    let document = try XniffTraceParser.parse(data: makeMachCapture())
    let event = try #require(document.events.first)
    let mach = try #require(event.machMessage)
    let metadata = try #require(mach.metadata)
    let header = try #require(mach.header)
    let trailer = try #require(mach.trailer)

    #expect(event.api == .machMessage)
    #expect(event.peerProcessID == 4_321)
    #expect(event.peerAuditToken?[5] == 4_321)
    #expect(metadata.option == 3)
    #expect(metadata.messageSize == 24)
    #expect(metadata.copiedLength == 24)
    #expect(metadata.messageAddress == 0x1234_5678)
    #expect(metadata.descriptorCount == 2)
    #expect(metadata.priority == 7)
    #expect(metadata.timeout == 42)
    #expect(header.messageID == 8_675_309)
    #expect(header.remotePort == 0x1111)
    #expect(header.localPort == 0x2222)
    #expect(trailer.sequenceNumber == 9)
    #expect(trailer.securityToken == [10, 11])
    #expect(trailer.senderProcessID == 4_321)

    #expect(event.payloads.map(\.kind) == [
        .machMessage, .machTrailer, .machOutOfLineData, .machPortArray,
    ])
    #expect(document.data(for: event.payloads[2]) == Data([0xDE, 0xAD, 0xBE, 0xEF]))
    #expect(mach.descriptors.count == 2)
    #expect(mach.descriptors[0].typeLabel == "Out-of-line data")
    #expect(mach.descriptors[0].capturedPayload?.descriptorIndex == 0)
    #expect(mach.descriptors[1].typeLabel == "Out-of-line ports")
    #expect(mach.descriptors[1].capturedPorts == [0x4444, 0x5555])
}

@Test func usesMachInspectorInsteadOfRawXPCForMachPayloads() throws {
    let document = try XniffTraceParser.parse(data: makeMachCapture())
    let payload = try #require(document.events.first?.payloads.first)
    let data = document.data(for: payload)
    let value = EmbeddedPayloadDecoder.decode(data, format: payload.format)
    let inspections = BodyInspectorRegistry.standard.inspections(
        for: value,
        data: data,
        payloadKind: payload.kind
    )

    #expect(inspections.contains { $0.id == StandardBodyInspectorID.mach })
    #expect(!inspections.contains { $0.id == StandardBodyInspectorID.rawXPC })
    #expect(inspections.first { $0.id == StandardBodyInspectorID.mach }?.tree?.summary == "Mach message")
}

private func makeMachCapture() -> Data {
    var fixed = Data()
    fixed.appendLE(UInt32(99))
    fixed.appendLE(UInt32(7))
    fixed.appendLE(UInt64(1_000))
    fixed.appendLE(UInt16(1))
    fixed.appendLE(UInt16(1))
    fixed.appendLE(UInt32(0))

    var invocation = Data()
    invocation.appendLE(UInt32(1))
    invocation.appendLE(UInt32(1))
    invocation.appendLE(UInt32(3))
    invocation.appendLE(UInt32(0))
    invocation.appendLE(UInt32(24))
    invocation.appendLE(UInt32(24))
    invocation.appendLE(UInt64(0x1234_5678))
    invocation.appendLE(UInt64(0))
    invocation.appendLE(UInt64(0))
    invocation.appendLE(UInt32(2))
    invocation.appendLE(UInt32(7))
    invocation.appendLE(UInt64(42))
    for argument in UInt64(1)...UInt64(8) { invocation.appendLE(argument) }

    var message = Data()
    message.appendLE(UInt32(0x8000_0000))
    message.appendLE(UInt32(24))
    message.appendLE(UInt32(0x1111))
    message.appendLE(UInt32(0x2222))
    message.appendLE(UInt32(0x3333))
    message.appendLE(UInt32(bitPattern: Int32(8_675_309)))

    var trailer = Data()
    trailer.appendLE(UInt32(0))
    trailer.appendLE(UInt32(52))
    trailer.appendLE(UInt32(9))
    trailer.appendLE(UInt32(10))
    trailer.appendLE(UInt32(11))
    for index in 0..<8 {
        trailer.appendLE(index == 5 ? UInt32(4_321) : UInt32(index))
    }

    var body = fixed
    body.appendSection(type: 1, payload: invocation)
    body.appendSection(type: 2, payload: message)
    body.appendSection(type: 3, payload: trailer)
    body.appendSection(type: 4, payload: descriptor(
        index: 0, type: 1, flags: 3, address: 0x1000,
        size: 4, count: 0, elementSize: 0
    ))
    body.appendSection(type: 5, payload: Data([0xDE, 0xAD, 0xBE, 0xEF]))
    body.appendSection(type: 4, payload: descriptor(
        index: 1, type: 2, flags: 17, address: 0x2000,
        size: 8, count: 2, elementSize: 4
    ))
    var ports = Data()
    ports.appendLE(UInt32(0x4444))
    ports.appendLE(UInt32(0x5555))
    body.appendSection(type: 6, payload: ports)

    var record = Data()
    record.appendLE(UInt32(16 + body.count))
    record.appendLE(UInt16(1))
    record.appendLE(UInt16(1))
    record.appendLE(UInt64(1))
    record.append(body)

    var file = Data()
    file.appendLE(UInt32(0x584e4246))
    file.appendLE(UInt16(2))
    file.appendLE(UInt16(0))
    file.append(record)
    return file
}

private func descriptor(
    index: UInt32,
    type: UInt16,
    flags: UInt16,
    address: UInt64,
    size: UInt32,
    count: UInt32,
    elementSize: UInt32
) -> Data {
    var data = Data()
    data.appendLE(index)
    data.appendLE(type)
    data.appendLE(flags)
    data.appendLE(address)
    data.appendLE(size)
    data.appendLE(count)
    data.appendLE(elementSize)
    data.appendLE(UInt32(0))
    data.appendLE(UInt32(0))
    data.appendLE(UInt32(0))
    return data
}

private extension Data {
    mutating func appendLE<T: FixedWidthInteger>(_ value: T) {
        var littleEndian = value.littleEndian
        Swift.withUnsafeBytes(of: &littleEndian) { append(contentsOf: $0) }
    }

    mutating func appendSection(type: UInt16, payload: Data) {
        appendLE(type)
        appendLE(UInt16(0))
        appendLE(UInt32(payload.count))
        append(payload)
    }
}
