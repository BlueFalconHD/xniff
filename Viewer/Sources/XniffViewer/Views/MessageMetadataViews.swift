import SwiftUI
import XniffViewerCore

struct MessageHeadersView: View {
    let event: TraceEvent
    let payloads: [TracePayloadSlice]

    private var rows: [HeaderRow] {
        var result = [
            HeaderRow("API", event.api.label),
            HeaderRow("Role", event.role.label),
            HeaderRow("Function", event.functionName),
            HeaderRow("Direction", event.direction.label),
            HeaderRow("Process ID", String(event.processID)),
            HeaderRow("Thread ID", String(format: "0x%08X", event.threadID)),
            HeaderRow("Sequence", String(event.sequence)),
            HeaderRow("Timestamp", String(format: "+%.6f s", event.relativeSeconds)),
        ]
        if let callID = event.callID { result.append(HeaderRow("Call ID", String(callID))) }
        if let service = event.serviceName { result.append(HeaderRow("Service", service)) }
        if let peer = event.peerProcessID { result.append(HeaderRow("Peer PID", String(peer))) }
        if let token = event.peerAuditToken, token.count >= 8 {
            result.append(HeaderRow("Peer PID version", String(token[7])))
            result.append(HeaderRow(
                "Peer audit token",
                token.map { String(format: "%08X", $0) }.joined(separator: " ")
            ))
        }
        if let object = event.xpcObjectID, let kind = event.xpcObjectKind {
            result.append(HeaderRow(
                kind == .connection ? "XPC connection" : "XPC session",
                String(format: "0x%llX", object)
            ))
        }
        result.append(HeaderRow("Return value", String(format: "0x%llX", event.returnValue)))
        for (index, argument) in event.arguments.enumerated() where argument != 0 {
            result.append(HeaderRow("Argument \(index)", String(format: "0x%llX", argument)))
        }
        for payload in payloads {
            let size = payload.range.count.formatted()
            let original = payload.originalLength.formatted()
            let suffix = payload.isTruncated ? " (truncated from \(original))" : ""
            result.append(HeaderRow("\(payload.name) body", "\(size) bytes\(suffix)"))
        }
        return result
    }

    var body: some View {
        Table(rows) {
            TableColumn("Header", value: \.name)
                .width(min: 120, ideal: 160, max: 220)
            TableColumn("Value") { row in
                Text(row.value)
                    .font(.system(.body, design: .monospaced))
                    .textSelection(.enabled)
            }
        }
    }
}

private struct HeaderRow: Identifiable {
    let id: String
    let name: String
    let value: String

    init(_ name: String, _ value: String) {
        self.id = "\(name)-\(value)"
        self.name = name
        self.value = value
    }
}

struct BacktraceView: View {
    let frames: [TraceFrame]

    var body: some View {
        if frames.isEmpty {
            InspectorPlaceholderView(
                title: "No Backtrace",
                systemImage: "point.3.connected.trianglepath.dotted",
                description: "Set XNIFF_BACKTRACE=1 while capturing to include backtraces."
            )
        } else {
            Table(frames) {
                TableColumn("#") { frame in
                    Text(frame.id, format: .number).monospacedDigit()
                }
                .width(35)
                TableColumn("Image") { frame in
                    Text(frame.imagePath.map { URL(fileURLWithPath: $0).lastPathComponent } ?? "—")
                        .lineLimit(1)
                        .help(frame.imagePath ?? "")
                }
                .width(min: 100, ideal: 150)
                TableColumn("Symbol") { frame in
                    Text(symbol(frame))
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                }
            }
        }
    }

    private func symbol(_ frame: TraceFrame) -> String {
        if let name = frame.symbolName {
            if let offset = frame.offset, offset != 0 {
                return "\(name) + 0x\(String(offset, radix: 16))"
            }
            return name
        }
        return String(format: "0x%llX", frame.programCounter)
    }
}
