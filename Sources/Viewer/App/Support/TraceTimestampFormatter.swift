import Foundation

enum TraceTimestampFormatter {
    static func string(from relativeSeconds: Double) -> String {
        String(format: "%.6f s", relativeSeconds)
    }
}
