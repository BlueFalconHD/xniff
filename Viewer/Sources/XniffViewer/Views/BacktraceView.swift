import SwiftUI
import XniffViewerCore

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
