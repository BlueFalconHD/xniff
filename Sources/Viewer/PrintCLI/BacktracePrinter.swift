import Foundation
import XniffViewerCore

enum BacktracePrinter {
    static func render(_ frames: [TraceFrame]) -> String? {
        guard !frames.isEmpty else { return nil }

        let frameLines = frames.map { frame in
            let imageName = frame.imagePath.map {
                URL(fileURLWithPath: $0).lastPathComponent
            } ?? "<unknown>"
            return "    #\(frame.id) \(imageName) \(symbol(for: frame))"
        }
        return (["  backtrace:"] + frameLines).joined(separator: "\n")
    }

    private static func symbol(for frame: TraceFrame) -> String {
        guard let name = frame.symbolName else {
            return String(format: "0x%llX", frame.programCounter)
        }
        guard let offset = frame.offset, offset != 0 else { return name }
        return "\(name) + 0x\(String(offset, radix: 16))"
    }
}
