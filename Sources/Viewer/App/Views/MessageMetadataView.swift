import SwiftUI
import XniffViewerCore

struct MessageMetadataView: View {
    let event: TraceEvent
    let payloads: [TracePayloadSlice]

    private var sections: [MetadataSection] {
        var messageFields = [
            MetadataField("Function", event.functionName, id: "function"),
            MetadataField("API", event.api.label, id: "api"),
            MetadataField("Role", event.role.label, id: "role"),
            MetadataField("Direction", event.direction.label, id: "direction"),
        ]
        if let service = event.serviceName {
            messageFields.insert(MetadataField("Service", service, id: "service"), at: 1)
        }

        var timingFields = [
            MetadataField(
                "Timestamp",
                TraceTimestampFormatter.string(from: event.relativeSeconds),
                id: "timestamp"
            ),
            MetadataField("Sequence", event.sequence.formatted(), id: "sequence"),
        ]
        if let callID = event.callID {
            timingFields.append(MetadataField("Call ID", callID.formatted(), id: "call-id"))
        }

        var processFields = [
            MetadataField("Process ID", event.processID.formatted(), id: "process-id"),
            MetadataField("Thread ID", String(format: "0x%08X", event.threadID), id: "thread-id"),
        ]
        if let peer = event.peerProcessID {
            processFields.append(MetadataField(
                "Peer process ID",
                peer.formatted(),
                id: "peer-process-id"
            ))
        }
        if let token = event.peerAuditToken, token.count >= 8 {
            processFields.append(MetadataField(
                "Peer PID version",
                token[7].formatted(),
                id: "peer-pid-version"
            ))
            processFields.append(MetadataField(
                "Peer audit token",
                token.map { String(format: "%08X", $0) }.joined(separator: " "),
                id: "peer-audit-token"
            ))
        }

        var sections = [
            MetadataSection("Message", systemImage: "message", fields: messageFields),
            MetadataSection("Timing", systemImage: "clock", fields: timingFields),
            MetadataSection("Process", systemImage: "cpu", fields: processFields),
        ]

        if let mach = event.machMessage {
            if let header = mach.header {
                sections.append(MetadataSection(
                    "Mach header",
                    systemImage: "envelope",
                    fields: [
                        MetadataField("Message ID", header.messageID.formatted(), id: "mach-id"),
                        MetadataField("Bits", hex(header.bits), id: "mach-bits"),
                        MetadataField("Message size", "\(header.size) bytes", id: "mach-size"),
                        MetadataField("Remote port", hex(header.remotePort), id: "mach-remote"),
                        MetadataField("Local port", hex(header.localPort), id: "mach-local"),
                        MetadataField("Voucher port", hex(header.voucherPort), id: "mach-voucher"),
                    ]
                ))
            }
            if let metadata = mach.metadata {
                sections.append(MetadataSection(
                    "Mach invocation",
                    systemImage: "arrow.left.arrow.right",
                    fields: [
                        MetadataField("Options", hex(metadata.option), id: "mach-options"),
                        MetadataField("Original size", "\(metadata.messageSize) bytes", id: "mach-original-size"),
                        MetadataField("Captured size", "\(metadata.copiedLength) bytes", id: "mach-captured-size"),
                        MetadataField("Message address", hex(metadata.messageAddress), id: "mach-address"),
                        MetadataField("Auxiliary address", hex(metadata.auxiliaryAddress), id: "mach-aux-address"),
                        MetadataField("Descriptor count", metadata.descriptorCount.formatted(), id: "mach-descriptor-count"),
                        MetadataField("Priority", metadata.priority.formatted(), id: "mach-priority"),
                        MetadataField("Timeout", metadata.timeout.formatted(), id: "mach-timeout"),
                    ]
                ))
            }
            if let trailer = mach.trailer {
                var fields = [
                    MetadataField("Type", trailer.type.formatted(), id: "mach-trailer-type"),
                    MetadataField("Size", "\(trailer.size) bytes", id: "mach-trailer-size"),
                ]
                if let sequence = trailer.sequenceNumber {
                    fields.append(MetadataField(
                        "Sequence number", sequence.formatted(), id: "mach-trailer-sequence"
                    ))
                }
                if let token = trailer.securityToken {
                    fields.append(MetadataField(
                        "Security token", token.map(hex).joined(separator: " "),
                        id: "mach-security-token"
                    ))
                }
                if let token = trailer.auditToken {
                    fields.append(MetadataField(
                        "Audit token", token.map(hex).joined(separator: " "),
                        id: "mach-audit-token"
                    ))
                }
                sections.append(MetadataSection(
                    "Mach trailer", systemImage: "person.badge.shield.checkmark", fields: fields
                ))
            }
            for descriptor in mach.descriptors {
                var fields = [
                    MetadataField("Type", descriptor.typeLabel, id: "type"),
                    MetadataField("Flags", hex(descriptor.flags), id: "flags"),
                    MetadataField("Address", hex(descriptor.address), id: "address"),
                    MetadataField("Size", "\(descriptor.size) bytes", id: "size"),
                ]
                if descriptor.count != 0 {
                    fields.append(MetadataField(
                        "Count", descriptor.count.formatted(), id: "count"
                    ))
                }
                if descriptor.elementSize != 0 {
                    fields.append(MetadataField(
                        "Element size", "\(descriptor.elementSize) bytes", id: "element-size"
                    ))
                }
                if descriptor.portName != 0 {
                    fields.append(MetadataField(
                        "Port name", hex(descriptor.portName), id: "port-name"
                    ))
                }
                if descriptor.portDisposition != 0 {
                    fields.append(MetadataField(
                        "Port disposition", descriptor.portDisposition.formatted(),
                        id: "port-disposition"
                    ))
                }
                if let payload = descriptor.capturedPayload {
                    fields.append(MetadataField(
                        "Captured payload", "\(payload.range.count) bytes", id: "payload"
                    ))
                }
                if !descriptor.capturedPorts.isEmpty {
                    fields.append(MetadataField(
                        "Captured ports", descriptor.capturedPorts.map(hex).joined(separator: " "),
                        id: "ports"
                    ))
                }
                sections.append(MetadataSection(
                    "Mach descriptor #\(descriptor.index)",
                    systemImage: "shippingbox",
                    fields: fields
                ))
            }
        }

        if let object = event.xpcObjectID, let kind = event.xpcObjectKind {
            var xpcFields = [
                MetadataField(
                    kind == .connection ? "Connection" : "Session",
                    String(format: "0x%llX", object),
                    id: "object"
                ),
            ]
            if let lifecycle = event.xpcObjectLifecycle {
                xpcFields.append(MetadataField(
                    "Lifecycle",
                    lifecycleLabel(lifecycle),
                    id: "lifecycle"
                ))
            }
            sections.append(MetadataSection(
                "XPC",
                systemImage: "point.3.connected.trianglepath.dotted",
                fields: xpcFields
            ))
        }

        var resultFields = [
            MetadataField(
                "Return value",
                String(format: "0x%llX", event.returnValue),
                id: "return-value"
            ),
        ]
        for (index, argument) in event.arguments.enumerated() where argument != 0 {
            resultFields.append(MetadataField(
                "Argument \(index)",
                String(format: "0x%llX", argument),
                id: "argument-\(index)"
            ))
        }
        sections.append(MetadataSection(
            "Result",
            systemImage: "arrow.turn.down.right",
            fields: resultFields
        ))

        var payloadFields: [MetadataField] = []
        for payload in payloads {
            let size = payload.range.count.formatted()
            let original = payload.originalLength.formatted()
            let suffix = payload.isTruncated ? " (truncated from \(original))" : ""
            payloadFields.append(MetadataField(
                "\(payload.name) body",
                "\(size) bytes\(suffix)",
                id: "payload-\(payload.id)"
            ))
        }
        if !payloadFields.isEmpty {
            sections.append(MetadataSection(
                "Payloads",
                systemImage: "doc",
                fields: payloadFields
            ))
        }

        return sections
    }

    var body: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 12) {
                ForEach(sections) { section in
                    MetadataSectionView(section: section)
                }
            }
            .padding(12)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func lifecycleLabel(_ lifecycle: XPCObjectLifecycle) -> String {
        switch lifecycle {
        case .observed: "Observed"
        case .created: "Created"
        case .cancelled: "Cancelled"
        }
    }

    private func hex<T: FixedWidthInteger>(_ value: T) -> String {
        String(format: "0x%llX", UInt64(value))
    }
}

private struct MetadataSection: Identifiable {
    let id: String
    let title: String
    let systemImage: String
    let fields: [MetadataField]

    init(_ title: String, systemImage: String, fields: [MetadataField]) {
        id = title
        self.title = title
        self.systemImage = systemImage
        self.fields = fields
    }
}

private struct MetadataField: Identifiable {
    let id: String
    let label: String
    let value: String

    init(_ label: String, _ value: String, id: String) {
        self.id = id
        self.label = label
        self.value = value
    }
}

private struct MetadataSectionView: View {
    let section: MetadataSection

    var body: some View {
        GroupBox {
            Grid(alignment: .topLeading, horizontalSpacing: 16, verticalSpacing: 0) {
                ForEach(Array(section.fields.enumerated()), id: \.element.id) { index, field in
                    GridRow(alignment: .firstTextBaseline) {
                        Text(field.label)
                            .foregroundStyle(.secondary)
                            .frame(minWidth: 100, alignment: .trailing)

                        Text(field.value)
                            .font(.system(.body, design: .monospaced))
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .padding(.vertical, 6)

                    if index < section.fields.count - 1 {
                        Divider()
                            .gridCellColumns(2)
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        } label: {
            Label(section.title, systemImage: section.systemImage)
                .font(.headline)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
