import Foundation

public struct MachPayloadBodyInspector: TraceBodyInspector {
    public let identifier = StandardBodyInspectorID.mach
    public let parentIdentifier: String? = StandardBodyInspectorID.hex
    public let priority = 10

    public init() {}

    public func inspect(_ context: BodyInspectorContext) -> BodyInspection? {
        guard let kind = context.payloadKind, kind.isMach else { return nil }
        let value: TraceValue
        do {
            value = try decode(kind: kind, data: context.originalData)
        } catch {
            value = .error(error.localizedDescription)
        }
        return BodyInspection(
            id: identifier,
            name: "Mach",
            priority: priority,
            parentID: parentIdentifier,
            content: .tree(value)
        )
    }

    private func decode(kind: TracePayloadKind, data: Data) throws -> TraceValue {
        switch kind {
        case .machMessage:
            guard let header = try MachWireDecoder.header(
                data: data, start: 0, end: data.count
            ) else {
                return .error("Mach message header is truncated")
            }
            return .object(type: "Mach message", fields: [
                TraceField(name: "bits", value: .unsigned(UInt64(header.bits))),
                TraceField(name: "size", value: .unsigned(UInt64(header.size))),
                TraceField(name: "remote port", value: .unsigned(UInt64(header.remotePort))),
                TraceField(name: "local port", value: .unsigned(UInt64(header.localPort))),
                TraceField(name: "voucher port", value: .unsigned(UInt64(header.voucherPort))),
                TraceField(name: "message ID", value: .signed(Int64(header.messageID))),
            ])
        case .machTrailer:
            guard let trailer = try MachWireDecoder.trailer(
                data: data, start: 0, end: data.count
            ) else {
                return .error("Mach trailer is truncated")
            }
            var fields = [
                TraceField(name: "type", value: .unsigned(UInt64(trailer.type))),
                TraceField(name: "size", value: .unsigned(UInt64(trailer.size))),
            ]
            if let sequenceNumber = trailer.sequenceNumber {
                fields.append(TraceField(
                    name: "sequence number",
                    value: .unsigned(UInt64(sequenceNumber))
                ))
            }
            if let senderProcessID = trailer.senderProcessID {
                fields.append(TraceField(
                    name: "sender process ID",
                    value: .unsigned(UInt64(senderProcessID))
                ))
            }
            if let auditToken = trailer.auditToken {
                fields.append(TraceField(
                    name: "audit token",
                    value: .array(auditToken.map { .unsigned(UInt64($0)) })
                ))
            }
            return .object(type: "Mach trailer", fields: fields)
        case .machPortArray:
            let ports = try MachWireDecoder.ports(data: data, start: 0, end: data.count)
            return .object(type: "Mach port array", fields: [
                TraceField(
                    name: "ports",
                    value: .array(ports.map { .unsigned(UInt64($0)) })
                ),
            ])
        case .machOutOfLineData:
            return .object(type: "Mach out-of-line data", fields: [
                TraceField(name: "length", value: .unsigned(UInt64(data.count))),
            ])
        default:
            return .error("Unsupported Mach payload")
        }
    }
}
