import AppKit
import SwiftUI
import XniffViewerCore

struct BodyTreeView: NSViewRepresentable {
    let payloadID: String
    let value: TraceValue
    let showInHex: (Range<Int>) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator()
    }

    func makeNSView(context: Context) -> NSScrollView {
        let outline = BodyOutlineView()
        outline.headerView = nil
        outline.rowSizeStyle = .small
        outline.usesAlternatingRowBackgroundColors = false
        outline.columnAutoresizingStyle = .lastColumnOnlyAutoresizingStyle
        outline.indentationPerLevel = 14

        let column = NSTableColumn(identifier: NSUserInterfaceItemIdentifier("Body"))
        column.resizingMask = .autoresizingMask
        outline.addTableColumn(column)
        outline.outlineTableColumn = column
        outline.dataSource = context.coordinator
        outline.delegate = context.coordinator
        outline.onShowInHex = showInHex

        let scrollView = NSScrollView()
        scrollView.hasVerticalScroller = true
        scrollView.hasHorizontalScroller = true
        scrollView.autohidesScrollers = true
        scrollView.documentView = outline

        context.coordinator.install(payloadID: payloadID, value: value, outline: outline)
        return scrollView
    }

    func updateNSView(_ scrollView: NSScrollView, context: Context) {
        guard let outline = scrollView.documentView as? BodyOutlineView else { return }
        outline.onShowInHex = showInHex
        guard context.coordinator.payloadID != payloadID else { return }
        context.coordinator.install(payloadID: payloadID, value: value, outline: outline)
    }

    @MainActor
    final class Coordinator: NSObject, NSOutlineViewDataSource, NSOutlineViewDelegate {
        fileprivate var payloadID: String?
        private var root: BodyNode?

        func install(payloadID: String, value: TraceValue, outline: NSOutlineView) {
            self.payloadID = payloadID
            root = BodyNode(name: "", value: value, sourceRange: nil, identity: "body")
            outline.reloadData()
        }

        func outlineView(_ outlineView: NSOutlineView, numberOfChildrenOfItem item: Any?) -> Int {
            if item == nil, let root, root.childCount == 0 { return 1 }
            return (item as? BodyNode ?? root)?.childCount ?? 0
        }

        func outlineView(_ outlineView: NSOutlineView, child index: Int, ofItem item: Any?) -> Any {
            if item == nil, let root, root.childCount == 0, index == 0 { return root }
            return (item as? BodyNode ?? root)?.child(at: index) ?? BodyNode.error(index: index)
        }

        func outlineView(_ outlineView: NSOutlineView, isItemExpandable item: Any) -> Bool {
            (item as? BodyNode)?.childCount ?? 0 > 0
        }

        func outlineView(
            _ outlineView: NSOutlineView,
            viewFor tableColumn: NSTableColumn?,
            item: Any
        ) -> NSView? {
            guard let node = item as? BodyNode else { return nil }
            let identifier = NSUserInterfaceItemIdentifier("BodyCell")
            let cell = outlineView.makeView(withIdentifier: identifier, owner: nil) as? BodyCellView
                ?? BodyCellView(identifier: identifier)
            cell.configure(with: node)
            return cell
        }

        func outlineView(_ outlineView: NSOutlineView, shouldSelectItem item: Any) -> Bool {
            true
        }
    }
}

@MainActor
private final class BodyOutlineView: NSOutlineView {
    var onShowInHex: ((Range<Int>) -> Void)?
    private weak var contextualNode: BodyNode?

    override func menu(for event: NSEvent) -> NSMenu? {
        let point = convert(event.locationInWindow, from: nil)
        let clickedRow = row(at: point)
        guard clickedRow >= 0, let node = item(atRow: clickedRow) as? BodyNode else { return nil }
        contextualNode = node
        selectRowIndexes(IndexSet(integer: clickedRow), byExtendingSelection: false)

        let menu = NSMenu()
        if node.sourceRange != nil {
            let show = NSMenuItem(title: "Show in Hex", action: #selector(showContextInHex), keyEquivalent: "")
            show.target = self
            menu.addItem(show)
        }
        let copy = NSMenuItem(title: "Copy Value", action: #selector(copyContextValue), keyEquivalent: "")
        copy.target = self
        menu.addItem(copy)
        return menu
    }

    @objc private func showContextInHex() {
        guard let range = contextualNode?.sourceRange else { return }
        onShowInHex?(range)
    }

    @objc private func copyContextValue() {
        guard let text = contextualNode?.copyText else { return }
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}

@MainActor
private final class BodyCellView: NSTableCellView {
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

    func configure(with node: BodyNode) {
        keyLabel.stringValue = node.name
        valueLabel.stringValue = node.detail
        keyLabel.textColor = node.isPreview ? .tertiaryLabelColor : .labelColor
        valueLabel.textColor = node.isError ? .systemRed : .secondaryLabelColor
        let font = node.isPreview ? NSFont.monospacedSystemFont(ofSize: 11, weight: .regular) : NSFont.systemFont(ofSize: 12)
        keyLabel.font = font
        valueLabel.font = node.isMonospaced
            ? NSFont.monospacedSystemFont(ofSize: 11, weight: .regular)
            : NSFont.systemFont(ofSize: 12)
        toolTip = node.copyText
    }
}

@MainActor
private final class BodyNode: NSObject {
    let name: String
    let value: TraceValue
    let sourceRange: Range<Int>?
    let identity: String
    let isPreview: Bool
    private var cachedChildren: [Int: BodyNode] = [:]

    init(
        name: String,
        value: TraceValue,
        sourceRange: Range<Int>?,
        identity: String,
        isPreview: Bool = false
    ) {
        let unwrapped = Self.unwrap(value, inheritedRange: sourceRange)
        self.name = name
        self.value = unwrapped.value
        self.sourceRange = unwrapped.range
        self.identity = identity
        self.isPreview = isPreview
    }

    static func error(index: Int) -> BodyNode {
        BodyNode(
            name: "Invalid child \(index)",
            value: .error("The decoded tree is inconsistent"),
            sourceRange: nil,
            identity: "error.\(index)"
        )
    }

    var childCount: Int {
        switch value {
        case .array(let values): values.count
        case .dictionary(let fields), .object(_, let fields): fields.count
        case .data(let data, let interpretation): (data.isEmpty ? 0 : 1) + (interpretation == nil ? 0 : 1)
        case .sourced: 0
        default: 0
        }
    }

    func child(at index: Int) -> BodyNode {
        if let cached = cachedChildren[index] { return cached }
        let child = makeChild(at: index)
        cachedChildren[index] = child
        return child
    }

    var detail: String {
        switch value {
        case .null: "null"
        case .bool(let value): value ? "true" : "false"
        case .signed(let value): String(value)
        case .unsigned(let value): String(value)
        case .double(let value): String(value)
        case .string(let value): value
        case .data(let data, _): "Data (\(data.count.formatted()) bytes)"
        case .array(let values): "Array (\(values.count.formatted()) items)"
        case .dictionary(let fields): "Dictionary (\(fields.count.formatted()) keys)"
        case .object(let type, _): type
        case .reference(let index): "↩︎ object \(index)"
        case .sourced(_, let nested): nested.summary
        case .error(let message): message
        }
    }

    var copyText: String { detail.isEmpty ? name : detail }
    var isError: Bool { if case .error = value { true } else { false } }
    var isMonospaced: Bool {
        switch value {
        case .signed, .unsigned, .double, .reference: true
        default: false
        }
    }

    private func makeChild(at index: Int) -> BodyNode {
        switch value {
        case .array(let values) where values.indices.contains(index):
            return BodyNode(
                name: "[\(index)]",
                value: values[index],
                sourceRange: sourceRange,
                identity: "\(identity).\(index)"
            )
        case .dictionary(let fields) where fields.indices.contains(index):
            let field = fields[index]
            return BodyNode(
                name: field.name,
                value: field.value,
                sourceRange: sourceRange,
                identity: "\(identity).\(index).\(field.name)"
            )
        case .object(_, let fields) where fields.indices.contains(index):
            let field = fields[index]
            return BodyNode(
                name: field.name,
                value: field.value,
                sourceRange: sourceRange,
                identity: "\(identity).\(index).\(field.name)"
            )
        case .data(let data, let interpretation):
            if !data.isEmpty && index == 0 {
                let preview = data.prefix(48).map { String(format: "%02X", $0) }.joined()
                return BodyNode(
                    name: preview + (data.count > 48 ? "…" : ""),
                    value: .string(""),
                    sourceRange: sourceRange,
                    identity: "\(identity).preview",
                    isPreview: true
                )
            }
            if let interpretation {
                let interpretationIndex = data.isEmpty ? 0 : 1
                if index == interpretationIndex {
                    let decoded = Self.unwrap(interpretation, inheritedRange: sourceRange)
                    if case .object(let type, let fields) = decoded.value {
                        return BodyNode(
                            name: type,
                            value: .dictionary(fields),
                            sourceRange: decoded.range,
                            identity: "\(identity).decoded"
                        )
                    }
                    return BodyNode(
                        name: "Decoded value",
                        value: decoded.value,
                        sourceRange: decoded.range,
                        identity: "\(identity).decoded"
                    )
                }
            }
            fallthrough
        default:
            return Self.error(index: index)
        }
    }

    private static func unwrap(
        _ value: TraceValue,
        inheritedRange: Range<Int>?
    ) -> (value: TraceValue, range: Range<Int>?) {
        if case .sourced(let range, let nested) = value {
            return unwrap(nested, inheritedRange: range)
        }
        return (value, inheritedRange)
    }
}
