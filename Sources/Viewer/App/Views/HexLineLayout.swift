import Foundation

enum HexLineLayout {
    static let bytesPerLine = 16
    static let lineHeight: CGFloat = 17

    static func lineCount(forByteCount byteCount: Int) -> Int {
        guard byteCount > 0 else { return 0 }
        return (byteCount - 1) / bytesPerLine + 1
    }

    static func visibleLines(byteCount: Int, in dirtyRect: CGRect) -> Range<Int> {
        let lineCount = lineCount(forByteCount: byteCount)
        guard lineCount > 0 else { return 0..<0 }
        guard dirtyRect.minY.isFinite, dirtyRect.maxY.isFinite else {
            return 0..<lineCount
        }

        let firstLine = boundedLineIndex(
            floor(dirtyRect.minY / lineHeight),
            lineCount: lineCount
        )
        let finalLine = boundedLineIndex(
            ceil(dirtyRect.maxY / lineHeight) + 1,
            lineCount: lineCount
        )
        guard firstLine < finalLine else { return firstLine..<firstLine }
        return firstLine..<finalLine
    }

    private static func boundedLineIndex(_ value: CGFloat, lineCount: Int) -> Int {
        guard value > 0 else { return 0 }
        guard value < CGFloat(lineCount) else { return lineCount }
        return Int(value)
    }
}
