import Foundation
import XniffViewerCore

enum TraceCallPrinter {
    static func render(
        _ call: TraceCall,
        document: TraceDocument,
        options: CommandLineOptions
    ) -> String {
        var sections = [renderHeader(call)]
        let requestBody = call.request.flatMap { firstBody(in: $0, document: document) }

        if let request = call.request {
            sections.append(renderEvent(
                request,
                label: request.role.label.uppercased(),
                document: document,
                counterpartBody: nil,
                options: options
            ))
        }
        if let response = call.response {
            sections.append(renderEvent(
                response,
                label: "RESPONSE",
                document: document,
                counterpartBody: requestBody,
                options: options
            ))
        }
        if call.request == nil, call.response == nil {
            sections.append(renderEvent(
                call.primaryEvent,
                label: call.primaryEvent.role.label.uppercased(),
                document: document,
                counterpartBody: nil,
                options: options
            ))
        }
        return sections.joined(separator: "\n")
    }

    private static func renderHeader(_ call: TraceCall) -> String {
        var fields = [
            "call_id=\(call.id.callID)",
            "pid=\(call.processID)",
            "time=\(String(format: "+%.6f", call.relativeSeconds))",
            "function=\(call.functionName)",
        ]
        if let peerProcessID = call.peerProcessID {
            fields.append("peer_pid=\(peerProcessID)")
        }
        if let serviceName = call.serviceName {
            fields.append("service=\(serviceName)")
        }
        if let duration = call.durationSeconds {
            fields.append("duration=\(String(format: "%.6f", duration))s")
        }
        return "=== \(fields.joined(separator: " ")) ==="
    }

    private static func renderEvent(
        _ event: TraceEvent,
        label: String,
        document: TraceDocument,
        counterpartBody: TraceValue?,
        options: CommandLineOptions
    ) -> String {
        var lines = [
            "\(label): event_id=\(event.id) tid=\(event.threadID) api=\(event.api.label)"
        ]
        guard options.includeBodies else { return lines.joined(separator: "\n") }

        for payload in event.payloads {
            let data = document.data(for: payload)
            let value = EmbeddedPayloadDecoder.decode(data, format: payload.format)
            let inspections = BodyInspectorRegistry.standard.inspections(
                for: value,
                data: data,
                counterpartBody: counterpartBody
            )
            let inspection = options.rawXPC
                ? inspections.first { $0.id == StandardBodyInspectorID.rawXPC }
                : inspections.first { $0.tree != nil }
            let rendered = inspection?.tree.map { TraceValueTextRenderer.render($0) }
                ?? TraceValueTextRenderer.render(value)
            lines.append("  \(payload.name) [\(inspection?.name ?? "Raw XPC")]:")
            lines.append(indent(rendered, by: 4))
            if payload.isTruncated {
                lines.append("    <truncated: stored \(data.count) of \(payload.originalLength) bytes>")
            }
        }
        if event.payloads.isEmpty, !event.summary.isEmpty {
            lines.append("  \(event.summary)")
        }
        return lines.joined(separator: "\n")
    }

    private static func firstBody(in event: TraceEvent, document: TraceDocument) -> TraceValue? {
        event.payloads.first.map {
            EmbeddedPayloadDecoder.decode(document.data(for: $0), format: $0.format)
        }
    }

    private static func indent(_ text: String, by spaces: Int) -> String {
        let prefix = String(repeating: " ", count: spaces)
        return prefix + text.replacingOccurrences(of: "\n", with: "\n\(prefix)")
    }
}
