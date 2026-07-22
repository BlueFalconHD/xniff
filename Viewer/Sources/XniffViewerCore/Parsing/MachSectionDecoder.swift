import Foundation

struct MachSectionAccumulator {
    private struct DescriptorBuilder {
        let index: UInt32
        let type: UInt16
        let flags: UInt16
        let address: UInt64
        let size: UInt32
        let count: UInt32
        let elementSize: UInt32
        let portName: UInt32
        let portDisposition: UInt32
        var capturedPayload: TracePayloadSlice?
        var capturedPorts: [UInt32] = []

        var descriptor: MachDescriptor {
            MachDescriptor(
                index: index,
                type: type,
                flags: flags,
                address: address,
                size: size,
                count: count,
                elementSize: elementSize,
                portName: portName,
                portDisposition: portDisposition,
                capturedPayload: capturedPayload,
                capturedPorts: capturedPorts
            )
        }
    }

    private(set) var metadata: MachMessageMetadata?
    private(set) var header: MachMessageHeader?
    private(set) var trailer: MachMessageTrailer?
    private(set) var returnValue: UInt64?
    private(set) var arguments: [UInt64]?
    private(set) var payloads: [TracePayloadSlice] = []
    private var descriptors: [DescriptorBuilder] = []

    var details: MachMessageDetails? {
        guard metadata != nil || header != nil || trailer != nil || !descriptors.isEmpty else {
            return nil
        }
        return MachMessageDetails(
            metadata: metadata,
            header: header,
            trailer: trailer,
            descriptors: descriptors.map(\.descriptor)
        )
    }

    mutating func consume(
        sectionType: UInt16,
        data: Data,
        start: Int,
        end: Int
    ) throws -> Bool {
        switch sectionType {
        case 1:
            try decodeMetadata(data: data, start: start, end: end)
        case 2:
            header = try MachWireDecoder.header(data: data, start: start, end: end)
            payloads.append(TracePayloadSlice(
                kind: .machMessage,
                format: 0,
                originalLength: end - start,
                isTruncated: false,
                range: start..<end
            ))
        case 3:
            trailer = try MachWireDecoder.trailer(data: data, start: start, end: end)
            payloads.append(TracePayloadSlice(
                kind: .machTrailer,
                format: 0,
                originalLength: end - start,
                isTruncated: false,
                range: start..<end
            ))
        case 4:
            try decodeDescriptor(data: data, start: start, end: end)
        case 5:
            attachPayload(kind: .machOutOfLineData, range: start..<end)
        case 6:
            let ports = try MachWireDecoder.ports(data: data, start: start, end: end)
            attachPayload(kind: .machPortArray, range: start..<end, ports: ports)
        default:
            return false
        }
        return true
    }

    private mutating func decodeMetadata(data: Data, start: Int, end: Int) throws {
        guard end - start >= 128 else { return }
        var reader = BinaryReader(data: data, offset: start, end: end)
        _ = try reader.readUInt32() // API, already present in the fixed header
        _ = try reader.readUInt32() // direction, already present in the fixed header
        let optionLow = try reader.readUInt32()
        let optionHigh = try reader.readUInt32()
        let messageSize = try reader.readUInt32()
        let copiedLength = try reader.readUInt32()
        let messageAddress = try reader.readUInt64()
        let auxiliaryAddress = try reader.readUInt64()
        returnValue = try reader.readUInt64()
        let descriptorCount = try reader.readUInt32()
        let priority = try reader.readUInt32()
        let timeout = try reader.readUInt64()
        arguments = try (0..<8).map { _ in try reader.readUInt64() }
        metadata = MachMessageMetadata(
            option: UInt64(optionLow) | (UInt64(optionHigh) << 32),
            messageSize: messageSize,
            copiedLength: copiedLength,
            messageAddress: messageAddress,
            auxiliaryAddress: auxiliaryAddress,
            descriptorCount: descriptorCount,
            priority: priority,
            timeout: timeout
        )
    }

    private mutating func decodeDescriptor(data: Data, start: Int, end: Int) throws {
        guard end - start >= 40 else { return }
        var reader = BinaryReader(data: data, offset: start, end: end)
        descriptors.append(DescriptorBuilder(
            index: try reader.readUInt32(),
            type: try reader.readUInt16(),
            flags: try reader.readUInt16(),
            address: try reader.readUInt64(),
            size: try reader.readUInt32(),
            count: try reader.readUInt32(),
            elementSize: try reader.readUInt32(),
            portName: try reader.readUInt32(),
            portDisposition: try reader.readUInt32()
        ))
    }

    private mutating func attachPayload(
        kind: TracePayloadKind,
        range: Range<Int>,
        ports: [UInt32] = []
    ) {
        let descriptorIndex = descriptors.last?.index
        let payload = TracePayloadSlice(
            kind: kind,
            format: 0,
            originalLength: range.count,
            isTruncated: false,
            range: range,
            descriptorIndex: descriptorIndex
        )
        payloads.append(payload)
        guard !descriptors.isEmpty else { return }
        descriptors[descriptors.count - 1].capturedPayload = payload
        descriptors[descriptors.count - 1].capturedPorts = ports
    }
}

enum MachWireDecoder {
    static func header(data: Data, start: Int, end: Int) throws -> MachMessageHeader? {
        guard end - start >= 24 else { return nil }
        var reader = BinaryReader(data: data, offset: start, end: end)
        return MachMessageHeader(
            bits: try reader.readUInt32(),
            size: try reader.readUInt32(),
            remotePort: try reader.readUInt32(),
            localPort: try reader.readUInt32(),
            voucherPort: try reader.readUInt32(),
            messageID: Int32(bitPattern: try reader.readUInt32())
        )
    }

    static func trailer(data: Data, start: Int, end: Int) throws -> MachMessageTrailer? {
        guard end - start >= 8 else { return nil }
        var reader = BinaryReader(data: data, offset: start, end: end)
        let type = try reader.readUInt32()
        let size = try reader.readUInt32()
        let availableEnd = min(end, start + Int(size))
        reader = BinaryReader(data: data, offset: reader.offset, end: availableEnd)
        let sequenceNumber = reader.remaining >= 4 ? try reader.readUInt32() : nil
        let securityToken = reader.remaining >= 8
            ? try (0..<2).map { _ in try reader.readUInt32() }
            : nil
        let auditToken = reader.remaining >= 32
            ? try (0..<8).map { _ in try reader.readUInt32() }
            : nil
        return MachMessageTrailer(
            type: type,
            size: size,
            sequenceNumber: sequenceNumber,
            securityToken: securityToken,
            auditToken: auditToken
        )
    }

    static func ports(data: Data, start: Int, end: Int) throws -> [UInt32] {
        var reader = BinaryReader(data: data, offset: start, end: end)
        var ports: [UInt32] = []
        ports.reserveCapacity(reader.remaining / 4)
        while reader.remaining >= 4 {
            ports.append(try reader.readUInt32())
        }
        return ports
    }
}
