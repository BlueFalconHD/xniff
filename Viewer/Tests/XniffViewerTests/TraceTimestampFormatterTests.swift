import Testing
@testable import XniffViewer

@Test func formatsTimestampsWithoutALeadingPlus() {
    #expect(TraceTimestampFormatter.string(from: 1.25) == "1.250000 s")
}
