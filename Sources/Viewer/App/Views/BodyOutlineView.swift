import AppKit
import XniffViewerCore

@MainActor
final class BodyOutlineView: NSOutlineView {
    var payloadData = Data()
    var parentInspectorName: String?
    var onViewInParent: ((Range<Int>) -> Void)?

    private weak var contextualNode: BodyTreeNode?

    override func menu(for event: NSEvent) -> NSMenu? {
        let point = convert(event.locationInWindow, from: nil)
        let clickedRow = row(at: point)
        guard clickedRow >= 0,
              let node = item(atRow: clickedRow) as? BodyTreeNode else { return nil }

        contextualNode = node
        selectRowIndexes(IndexSet(integer: clickedRow), byExtendingSelection: false)

        let menu = NSMenu()
        if let parentInspectorName, node.sourceRange != nil {
            let viewInParent = NSMenuItem(
                title: "View in \(parentInspectorName)",
                action: #selector(viewContextInParent),
                keyEquivalent: ""
            )
            viewInParent.target = self
            menu.addItem(viewInParent)
            menu.addItem(.separator())
        }

        menu.addItem(menuItem(title: "Copy Value", action: #selector(copyContextValue)))
        menu.addItem(menuItem(title: "Copy Tree", action: #selector(copyContextTree)))
        if clippedRange(for: node) != nil {
            menu.addItem(menuItem(title: "Copy Hex", action: #selector(copyContextHex)))
        }
        return menu
    }

    @objc private func viewContextInParent() {
        guard let range = contextualNode?.sourceRange else { return }
        onViewInParent?(range)
    }

    @objc private func copyContextValue() {
        writeToPasteboard(contextualNode?.copyValue)
    }

    @objc private func copyContextTree() {
        guard let node = contextualNode else { return }
        writeToPasteboard(TraceValueTextRenderer.render(node.value, rootName: node.name))
    }

    @objc private func copyContextHex() {
        guard let node = contextualNode,
              let range = clippedRange(for: node) else { return }
        let text = payloadData[range]
            .map { String(format: "%02X", $0) }
            .joined(separator: " ")
        writeToPasteboard(text)
    }

    private func menuItem(title: String, action: Selector) -> NSMenuItem {
        let item = NSMenuItem(title: title, action: action, keyEquivalent: "")
        item.target = self
        return item
    }

    private func clippedRange(for node: BodyTreeNode) -> Range<Int>? {
        guard let range = node.sourceRange else { return nil }
        let lowerBound = max(0, min(payloadData.count, range.lowerBound))
        let upperBound = max(lowerBound, min(payloadData.count, range.upperBound))
        return lowerBound < upperBound ? lowerBound..<upperBound : nil
    }

    private func writeToPasteboard(_ text: String?) {
        guard let text else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}

@MainActor
final class BodyTreeCellView: NSTableCellView {
    private let keyLabel = NSTextField(labelWithString: "")
    private let valueLabel = NSTextField(labelWithString: "")

    init(identifier: NSUserInterfaceItemIdentifier) {
        super.init(frame: .zero)
        self.identifier = identifier
        keyLabel.setContentCompressionResistancePriority(.defaultHigh, for: .horizontal)
        valueLabel.textColor = .secondaryLabelColor
        valueLabel.lineBreakMode = .byTruncatingTail
        valueLabel.maximumNumberOfLines = 1

        let stack = NSStackView(views: [keyLabel, valueLabel])
        stack.orientation = .horizontal
        stack.alignment = .firstBaseline
        stack.spacing = 8
        stack.translatesAutoresizingMaskIntoConstraints = false
        addSubview(stack)
        NSLayoutConstraint.activate([
            stack.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 2),
            stack.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor, constant: -4),
            stack.centerYAnchor.constraint(equalTo: centerYAnchor),
        ])
    }

    required init?(coder: NSCoder) {
        nil
    }

    func configure(with node: BodyTreeNode) {
        keyLabel.stringValue = node.name
        valueLabel.stringValue = node.detail
        keyLabel.textColor = node.isPreview ? .tertiaryLabelColor : .labelColor
        valueLabel.textColor = node.isError ? .systemRed : .secondaryLabelColor
        keyLabel.font = node.isPreview
            ? NSFont.monospacedSystemFont(ofSize: 11, weight: .regular)
            : NSFont.systemFont(ofSize: 12)
        valueLabel.font = node.isMonospaced
            ? NSFont.monospacedSystemFont(ofSize: 11, weight: .regular)
            : NSFont.systemFont(ofSize: 12)
        toolTip = node.copyValue
    }
}
