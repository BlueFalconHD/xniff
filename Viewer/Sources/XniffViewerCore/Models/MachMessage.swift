import Foundation

public struct MachMessageMetadata: Sendable, Hashable {
    public let option: UInt64
    public let messageSize: UInt32
    public let copiedLength: UInt32
    public let messageAddress: UInt64
    public let auxiliaryAddress: UInt64
    public let descriptorCount: UInt32
    public let priority: UInt32
    public let timeout: UInt64
}

public struct MachMessageHeader: Sendable, Hashable {
    public let bits: UInt32
    public let size: UInt32
    public let remotePort: UInt32
    public let localPort: UInt32
    public let voucherPort: UInt32
    public let messageID: Int32
}

public struct MachMessageTrailer: Sendable, Hashable {
    public let type: UInt32
    public let size: UInt32
    public let sequenceNumber: UInt32?
    public let securityToken: [UInt32]?
    public let auditToken: [UInt32]?

    public var senderProcessID: UInt32? {
        guard let auditToken, auditToken.count >= 6, auditToken[5] != 0 else { return nil }
        return auditToken[5]
    }
}

public struct MachDescriptor: Sendable, Hashable, Identifiable {
    public let index: UInt32
    public let type: UInt16
    public let flags: UInt16
    public let address: UInt64
    public let size: UInt32
    public let count: UInt32
    public let elementSize: UInt32
    public let portName: UInt32
    public let portDisposition: UInt32
    public let capturedPayload: TracePayloadSlice?
    public let capturedPorts: [UInt32]

    public var id: UInt32 { index }

    public var typeLabel: String {
        switch type {
        case 0: "Port"
        case 1: "Out-of-line data"
        case 2: "Out-of-line ports"
        case 3: "Volatile out-of-line data"
        case 4: "Guarded port"
        default: "Unknown (\(type))"
        }
    }
}

public struct MachMessageDetails: Sendable, Hashable {
    public let metadata: MachMessageMetadata?
    public let header: MachMessageHeader?
    public let trailer: MachMessageTrailer?
    public let descriptors: [MachDescriptor]
}
