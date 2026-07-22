import AppKit
import SwiftUI
import XniffViewerCore

struct BodyTreeView: NSViewRepresentable {
    let payloadID: String
    let value: TraceValue
    let data: Data
    let highlightedRange: Range<Int>?
    let parentInspectorName: String?
    let viewInParent: (Range<Int>) -> Void

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

        let scrollView = NSScrollView()
        scrollView.hasVerticalScroller = true
        scrollView.hasHorizontalScroller = true
        scrollView.autohidesScrollers = true
        scrollView.documentView = outline

        configure(outline)
        context.coordinator.install(
            payloadID: payloadID,
            value: value,
            highlightedRange: highlightedRange,
            outline: outline
        )
        return scrollView
    }

    func updateNSView(_ scrollView: NSScrollView, context: Context) {
        guard let outline = scrollView.documentView as? BodyOutlineView else { return }
        configure(outline)
        context.coordinator.update(
            payloadID: payloadID,
            value: value,
            highlightedRange: highlightedRange,
            outline: outline
        )
    }

    private func configure(_ outline: BodyOutlineView) {
        outline.payloadData = data
        outline.parentInspectorName = parentInspectorName
        outline.onViewInParent = viewInParent
    }

    @MainActor
    final class Coordinator: NSObject, NSOutlineViewDataSource, NSOutlineViewDelegate {
        private var payloadID: String?
        private var highlightedRange: Range<Int>?
        private var root: BodyTreeNode?

        func install(
            payloadID: String,
            value: TraceValue,
            highlightedRange: Range<Int>?,
            outline: NSOutlineView
        ) {
            self.payloadID = payloadID
            self.highlightedRange = highlightedRange
            root = BodyTreeNode(name: "", value: value, sourceRange: nil)
            outline.reloadData()
            reveal(highlightedRange, in: outline)
        }

        func update(
            payloadID: String,
            value: TraceValue,
            highlightedRange: Range<Int>?,
            outline: NSOutlineView
        ) {
            guard self.payloadID == payloadID else {
                install(
                    payloadID: payloadID,
                    value: value,
                    highlightedRange: highlightedRange,
                    outline: outline
                )
                return
            }
            guard self.highlightedRange != highlightedRange else { return }
            self.highlightedRange = highlightedRange
            reveal(highlightedRange, in: outline)
        }

        func outlineView(_ outlineView: NSOutlineView, numberOfChildrenOfItem item: Any?) -> Int {
            if item == nil, let root, root.childCount == 0 { return 1 }
            return (item as? BodyTreeNode ?? root)?.childCount ?? 0
        }

        func outlineView(_ outlineView: NSOutlineView, child index: Int, ofItem item: Any?) -> Any {
            if item == nil, let root, root.childCount == 0, index == 0 { return root }
            return (item as? BodyTreeNode ?? root)?.child(at: index) ?? BodyTreeNode.error(index: index)
        }

        func outlineView(_ outlineView: NSOutlineView, isItemExpandable item: Any) -> Bool {
            (item as? BodyTreeNode)?.childCount ?? 0 > 0
        }

        func outlineView(
            _ outlineView: NSOutlineView,
            viewFor tableColumn: NSTableColumn?,
            item: Any
        ) -> NSView? {
            guard let node = item as? BodyTreeNode else { return nil }
            let identifier = NSUserInterfaceItemIdentifier("BodyCell")
            let cell = outlineView.makeView(withIdentifier: identifier, owner: nil) as? BodyTreeCellView
                ?? BodyTreeCellView(identifier: identifier)
            cell.configure(with: node)
            return cell
        }

        private func reveal(_ range: Range<Int>?, in outline: NSOutlineView) {
            guard let range,
                  let path = root?.bestPath(matching: range),
                  let target = path.last else {
                outline.deselectAll(nil)
                return
            }

            for ancestor in path.dropFirst().dropLast() {
                outline.expandItem(ancestor)
            }
            let row = outline.row(forItem: target)
            guard row >= 0 else { return }
            outline.selectRowIndexes(IndexSet(integer: row), byExtendingSelection: false)
            outline.scrollRowToVisible(row)
        }
    }
}
