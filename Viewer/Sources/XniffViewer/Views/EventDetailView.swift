import AppKit
import SwiftUI
import XniffViewerCore

struct EventDetailView: View {
    let store: TraceStore
    let event: TraceEvent?

    var body: some View {
        Group {
            if let event {
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 16) {
                        header(event)
                        metadata(event)
                        relatedTraffic(event)
                        payloads(event)
                    }
                    .padding(16)
                }
                .task(id: event.id) {
                    store.decodePayloads(for: event)
                }
            } else {
                ContentUnavailableView(
                    "No Event Selected",
                    systemImage: "sidebar.right",
                    description: Text("Select an event to inspect its decoded payload.")
                )
            }
        }
    }

    private func header(_ event: TraceEvent) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(event.role.label.uppercased())
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
            Text(event.functionName)
                .font(.title3.weight(.semibold))
                .textSelection(.enabled)
            if !event.summary.isEmpty {
                Text(event.summary)
                    .foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
        }
    }

    private func metadata(_ event: TraceEvent) -> some View {
        GroupBox("Event") {
            Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 7) {
                metadataRow("Time", String(format: "+%.6f s", event.relativeSeconds))
                metadataRow("API", event.api.label)
                metadataRow("Direction", event.direction.label)
                metadataRow("Process", String(event.processID))
                metadataRow("Thread", String(format: "0x%08x", event.threadID))
                if let callID = event.callID { metadataRow("Call", String(callID)) }
                if let peer = event.peerProcessID { metadataRow("Peer PID", String(peer)) }
                metadataRow("Return", String(format: "0x%llx", event.returnValue))
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.top, 4)
        }
    }

    @ViewBuilder
    private func relatedTraffic(_ event: TraceEvent) -> some View {
        let related = store.relatedEvents(to: event)
        if !related.isEmpty {
            GroupBox("Same Call") {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(related) { relatedEvent in
                        Button {
                            store.selectedEventID = relatedEvent.id
                        } label: {
                            HStack {
                                Text(relatedEvent.role.label)
                                    .font(.caption.weight(.medium))
                                Text(relatedEvent.functionName)
                                    .lineLimit(1)
                                Spacer()
                                Text(String(format: "+%.6f", relatedEvent.relativeSeconds))
                                    .foregroundStyle(.secondary)
                                    .monospacedDigit()
                            }
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                    }
                }
                .padding(.top, 4)
            }
        }
    }

    @ViewBuilder
    private func payloads(_ event: TraceEvent) -> some View {
        let _ = store.decodeRevision
        if event.payloads.isEmpty {
            GroupBox("Payload") {
                Text("No serialized body was captured for this event.")
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.top, 4)
            }
        } else {
            ForEach(event.payloads) { payload in
                GroupBox {
                    if let value = store.decodedValue(event: event, payload: payload) {
                        TraceValueView(name: payload.name, value: value)
                    } else {
                        ProgressView("Decoding \(payload.name)…")
                            .controlSize(.small)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                } label: {
                    HStack {
                        Text(payload.name)
                        Spacer()
                        Text("\(payload.range.count) bytes")
                            .foregroundStyle(.secondary)
                        if payload.isTruncated {
                            Text("TRUNCATED")
                                .font(.caption2.weight(.bold))
                                .foregroundStyle(.orange)
                        }
                    }
                }
            }
        }
    }

    private func metadataRow(_ name: String, _ value: String) -> some View {
        GridRow {
            Text(name).foregroundStyle(.secondary)
            Text(value)
                .font(.system(.body, design: .monospaced))
                .textSelection(.enabled)
        }
    }
}

struct TraceValueView: View {
    private let nodes: [TraceValueNode]

    init(name: String, value: TraceValue) {
        nodes = [TraceValueNode.make(name: name, value: value, path: "root")]
    }

    var body: some View {
        OutlineGroup(nodes, children: \.children) { node in
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Text(node.name)
                    .foregroundStyle(.secondary)
                if !node.detail.isEmpty {
                    Text(node.detail)
                        .foregroundStyle(node.isError ? .red : .primary)
                        .font(node.isHex ? .system(.caption, design: .monospaced) : .body)
                        .textSelection(.enabled)
                }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

private struct TraceValueNode: Identifiable {
    let id: String
    let name: String
    let detail: String
    let children: [TraceValueNode]?
    var isError = false
    var isHex = false

    static func make(name: String, value: TraceValue, path: String) -> TraceValueNode {
        switch value {
        case .array(let values):
            return TraceValueNode(
                id: path,
                name: name,
                detail: "[\(values.count)]",
                children: values.enumerated().map { index, value in
                    make(name: "[\(index)]", value: value, path: "\(path).\(index)")
                }
            )
        case .dictionary(let fields):
            return fieldContainer(name: name, detail: "{\(fields.count)}", fields: fields, path: path)
        case .object(let type, let fields):
            return fieldContainer(name: name, detail: "‹\(type)›", fields: fields, path: path)
        case .data(let data):
            let preview = data.prefix(512)
            var rows: [TraceValueNode] = []
            for offset in stride(from: 0, to: preview.count, by: 16) {
                let bytes = preview.dropFirst(offset).prefix(16)
                let hex = bytes.map { String(format: "%02x", $0) }.joined(separator: " ")
                    .padding(toLength: 47, withPad: " ", startingAt: 0)
                let ascii = bytes.map { (32...126).contains($0) ? String(UnicodeScalar($0)) : "." }.joined()
                rows.append(TraceValueNode(
                    id: "\(path).hex.\(offset)",
                    name: String(format: "%04x", offset),
                    detail: "\(hex)  \(ascii)",
                    children: nil,
                    isHex: true
                ))
            }
            if data.count > preview.count {
                rows.append(TraceValueNode(
                    id: "\(path).truncated",
                    name: "…",
                    detail: "\(data.count - preview.count) more bytes",
                    children: nil
                ))
            }
            return TraceValueNode(id: path, name: name, detail: "\(data.count) bytes", children: rows)
        case .string(let string):
            return TraceValueNode(id: path, name: name, detail: string, children: nil)
        case .bool(let bool):
            return TraceValueNode(id: path, name: name, detail: bool ? "true" : "false", children: nil)
        case .signed(let number):
            return TraceValueNode(id: path, name: name, detail: String(number), children: nil)
        case .unsigned(let number):
            return TraceValueNode(id: path, name: name, detail: String(number), children: nil)
        case .double(let number):
            return TraceValueNode(id: path, name: name, detail: String(number), children: nil)
        case .null:
            return TraceValueNode(id: path, name: name, detail: "null", children: nil)
        case .reference(let index):
            return TraceValueNode(id: path, name: name, detail: "↩︎ object \(index)", children: nil)
        case .error(let message):
            return TraceValueNode(id: path, name: name, detail: message, children: nil, isError: true)
        }
    }

    private static func fieldContainer(
        name: String,
        detail: String,
        fields: [TraceField],
        path: String
    ) -> TraceValueNode {
        TraceValueNode(
            id: path,
            name: name,
            detail: detail,
            children: fields.enumerated().map { index, field in
                make(name: field.name, value: field.value, path: "\(path).\(index).\(field.name)")
            }
        )
    }
}
