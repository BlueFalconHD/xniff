import Foundation
import Testing
@testable import XniffViewer

@Test func visibleHexLinesAreEmptyWhenRedrawStartsPastTheDocument() {
    let dirtyRect = CGRect(x: 0, y: 1_000, width: 700, height: 100)

    let lines = HexLineLayout.visibleLines(byteCount: 32, in: dirtyRect)

    #expect(lines.isEmpty)
}

@Test func visibleHexLinesAreClampedToTheDocument() {
    let dirtyRect = CGRect(x: 0, y: 17, width: 700, height: 17)

    let lines = HexLineLayout.visibleLines(byteCount: 48, in: dirtyRect)

    #expect(lines == 1..<3)
}

@Test func visibleHexLinesAreEmptyForAnEmptyPayload() {
    let lines = HexLineLayout.visibleLines(
        byteCount: 0,
        in: CGRect(x: 0, y: 0, width: 700, height: 100)
    )

    #expect(lines.isEmpty)
}
