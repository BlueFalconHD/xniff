import AppKit
import SwiftUI

struct HexView: View {
    let payloadID: UUID
    let data: Data
    let highlightedRange: Range<Int>?

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Text("\(data.count.formatted()) bytes")
                if let selectedRange {
                    Text(String(
                        format: "Selected 0x%X–0x%X (%d bytes)",
                        selectedRange.lowerBound,
                        selectedRange.upperBound,
                        selectedRange.count
                    ))
                    .foregroundStyle(.secondary)
                }
                Spacer()
            }
            .font(.caption.monospaced())
            .padding(.horizontal, 10)
            .frame(height: 28)
            Divider()

            HexScrollView(
                payloadID: payloadID,
                data: data,
                highlightedRange: selectedRange
            )
        }
    }

    private var selectedRange: Range<Int>? {
        guard let highlightedRange else { return nil }
        let lower = max(0, min(data.count, highlightedRange.lowerBound))
        let upper = max(lower, min(data.count, highlightedRange.upperBound))
        return lower < upper ? lower..<upper : nil
    }
}

private struct HexScrollView: NSViewRepresentable {
    let payloadID: UUID
    let data: Data
    let highlightedRange: Range<Int>?

    func makeCoordinator() -> Coordinator {
        Coordinator()
    }

    func makeNSView(context: Context) -> HexHostingScrollView {
        let scrollView = HexHostingScrollView()
        scrollView.hasVerticalScroller = true
        scrollView.hasHorizontalScroller = true
        scrollView.autohidesScrollers = true
        scrollView.drawsBackground = false
        scrollView.documentView = scrollView.hexDocumentView
        context.coordinator.update(
            payloadID: payloadID,
            data: data,
            highlightedRange: highlightedRange,
            scrollView: scrollView
        )
        return scrollView
    }

    func updateNSView(_ scrollView: HexHostingScrollView, context: Context) {
        context.coordinator.update(
            payloadID: payloadID,
            data: data,
            highlightedRange: highlightedRange,
            scrollView: scrollView
        )
    }

    @MainActor
    final class Coordinator {
        private var payloadID: UUID?
        private var highlightedRange: Range<Int>?

        func update(
            payloadID: UUID,
            data: Data,
            highlightedRange: Range<Int>?,
            scrollView: HexHostingScrollView
        ) {
            let payloadChanged = self.payloadID != payloadID
            let selectionChanged = self.highlightedRange != highlightedRange
            guard payloadChanged || selectionChanged else { return }

            self.payloadID = payloadID
            self.highlightedRange = highlightedRange
            scrollView.hexDocumentView.configure(
                data: data,
                highlightedRange: highlightedRange,
                resetScroll: payloadChanged
            )
            scrollView.layoutDocument()
            if let highlightedRange {
                scrollView.scrollTo(byteOffset: highlightedRange.lowerBound)
            } else if payloadChanged {
                scrollView.contentView.scroll(to: .zero)
                scrollView.reflectScrolledClipView(scrollView.contentView)
            }
        }
    }
}

@MainActor
private final class HexHostingScrollView: NSScrollView {
    let hexDocumentView = HexDocumentView()

    override func layout() {
        super.layout()
        layoutDocument()
    }

    func layoutDocument() {
        let size = hexDocumentView.documentSize(minimumWidth: contentSize.width)
        if hexDocumentView.frame.size != size {
            hexDocumentView.frame.size = size
        }
    }

    func scrollTo(byteOffset: Int) {
        layoutDocument()
        let row = byteOffset / HexDocumentView.bytesPerLine
        let targetY = max(0, CGFloat(row) * HexDocumentView.lineHeight - contentSize.height / 2)
        contentView.scroll(to: NSPoint(x: contentView.bounds.origin.x, y: targetY))
        reflectScrolledClipView(contentView)
    }
}

@MainActor
private final class HexDocumentView: NSView {
    static let bytesPerLine = 16
    static let lineHeight: CGFloat = 17

    private let font = NSFont.monospacedSystemFont(ofSize: 11, weight: .regular)
    private lazy var characterWidth = "0".size(withAttributes: normalAttributes).width
    private lazy var normalAttributes: [NSAttributedString.Key: Any] = [
        .font: font,
        .foregroundColor: NSColor.labelColor,
    ]
    private lazy var secondaryAttributes: [NSAttributedString.Key: Any] = [
        .font: font,
        .foregroundColor: NSColor.secondaryLabelColor,
    ]
    private lazy var highlightedAttributes: [NSAttributedString.Key: Any] = [
        .font: font,
        .foregroundColor: NSColor.white,
    ]

    private var data = Data()
    private var highlightedRange: Range<Int>?

    override var isFlipped: Bool { true }
    override var isOpaque: Bool { false }

    func configure(data: Data, highlightedRange: Range<Int>?, resetScroll: Bool) {
        self.data = data
        self.highlightedRange = highlightedRange
        needsDisplay = true
    }

    func documentSize(minimumWidth: CGFloat) -> NSSize {
        let lines = max(1, (data.count + Self.bytesPerLine - 1) / Self.bytesPerLine)
        return NSSize(
            width: max(minimumWidth, 690),
            height: CGFloat(lines) * Self.lineHeight + 16
        )
    }

    override func draw(_ dirtyRect: NSRect) {
        super.draw(dirtyRect)
        guard !data.isEmpty else {
            "No bytes".draw(at: NSPoint(x: 8, y: 8), withAttributes: secondaryAttributes)
            return
        }

        let firstLine = max(0, Int(dirtyRect.minY / Self.lineHeight))
        let finalLine = min(
            (data.count + Self.bytesPerLine - 1) / Self.bytesPerLine,
            Int(ceil(dirtyRect.maxY / Self.lineHeight)) + 1
        )
        for line in firstLine..<finalLine {
            drawLine(line)
        }
    }

    private func drawLine(_ line: Int) {
        let offset = line * Self.bytesPerLine
        let y = CGFloat(line) * Self.lineHeight + 2
        String(format: "%08X", offset)
            .draw(at: NSPoint(x: 8, y: y), withAttributes: secondaryAttributes)

        let hexStart: CGFloat = 78
        let byteStride = characterWidth * 3
        for column in 0..<Self.bytesPerLine {
            let index = offset + column
            guard index < data.count else { break }
            let groupGap = column >= 8 ? characterWidth : 0
            let x = hexStart + CGFloat(column) * byteStride + groupGap
            let highlighted = highlightedRange?.contains(index) == true
            if highlighted {
                NSColor.controlAccentColor.setFill()
                NSBezierPath(
                    roundedRect: NSRect(
                        x: x - 2,
                        y: y - 1,
                        width: characterWidth * 2 + 4,
                        height: Self.lineHeight - 1
                    ),
                    xRadius: 2,
                    yRadius: 2
                ).fill()
            }
            String(format: "%02X", data[index]).draw(
                at: NSPoint(x: x, y: y),
                withAttributes: highlighted ? highlightedAttributes : normalAttributes
            )
        }

        let asciiX = hexStart + CGFloat(Self.bytesPerLine) * byteStride + characterWidth * 3
        let end = min(data.count, offset + Self.bytesPerLine)
        let ascii = data[offset..<end].map { byte in
            (32...126).contains(byte) ? String(UnicodeScalar(byte)) : "."
        }.joined()
        ascii.draw(at: NSPoint(x: asciiX, y: y), withAttributes: secondaryAttributes)
    }
}
