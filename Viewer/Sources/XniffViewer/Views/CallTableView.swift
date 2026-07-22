import AppKit
import SwiftUI
import XniffViewerCore

struct CallTableView: View {
    @Bindable var store: TraceStore

    var body: some View {
        ZStack {
            CallTableRepresentable(
                calls: store.visibleCalls,
                selection: $store.selectedCallID,
                addPredicate: store.conjoin
            )

            if store.document != nil && store.visibleCalls.isEmpty && !store.isLoading {
                ContentUnavailableView(
                    store.predicate.isEmpty ? "No Calls" : "No Predicate Matches",
                    systemImage: "line.3.horizontal.decrease.circle",
                    description: Text(
                        store.predicate.isEmpty
                            ? "The capture does not contain any logical calls."
                            : store.predicate.text
                    )
                )
            }
        }
    }
}

private struct CallTableRepresentable: NSViewRepresentable {
    let calls: [TraceCall]
    @Binding var selection: TraceCallID?
    let addPredicate: (TracePredicateItem) -> Void

    func makeCoordinator() -> Coordinator {
        Coordinator(selection: $selection, addPredicate: addPredicate)
    }

    func makeNSView(context: Context) -> NSScrollView {
        let table = NSTableView()
        table.rowHeight = 24
        table.usesAlternatingRowBackgroundColors = true
        table.allowsMultipleSelection = false
        table.allowsEmptySelection = true
        table.columnAutoresizingStyle = .lastColumnOnlyAutoresizingStyle
        table.gridStyleMask = [.solidHorizontalGridLineMask]
        table.intercellSpacing = NSSize(width: 8, height: 0)
        table.delegate = context.coordinator
        table.dataSource = context.coordinator
        let menu = NSMenu()
        menu.delegate = context.coordinator
        table.menu = menu
        context.coordinator.table = table

        for specification in ColumnSpecification.all {
            let column = NSTableColumn(identifier: specification.id)
            column.title = specification.title
            column.width = specification.width
            column.minWidth = specification.minimumWidth
            column.maxWidth = specification.maximumWidth
            column.resizingMask = specification.resizingMask
            table.addTableColumn(column)
        }

        let scrollView = NSScrollView()
        scrollView.hasVerticalScroller = true
        scrollView.hasHorizontalScroller = true
        scrollView.autohidesScrollers = true
        scrollView.documentView = table

        context.coordinator.update(
            calls: calls,
            selection: $selection,
            addPredicate: addPredicate,
            table: table
        )
        return scrollView
    }

    func updateNSView(_ scrollView: NSScrollView, context: Context) {
        guard let table = scrollView.documentView as? NSTableView else { return }
        context.coordinator.update(
            calls: calls,
            selection: $selection,
            addPredicate: addPredicate,
            table: table
        )
    }

    @MainActor
    final class Coordinator: NSObject, NSTableViewDataSource, NSTableViewDelegate, NSMenuDelegate {
        private var calls: [TraceCall] = []
        private var callIDs: [TraceCallID] = []
        private var selection: Binding<TraceCallID?>
        private var addPredicate: (TracePredicateItem) -> Void
        private var menuPredicates: [TracePredicateItem] = []
        weak var table: NSTableView?

        init(
            selection: Binding<TraceCallID?>,
            addPredicate: @escaping (TracePredicateItem) -> Void
        ) {
            self.selection = selection
            self.addPredicate = addPredicate
        }

        func update(
            calls: [TraceCall],
            selection: Binding<TraceCallID?>,
            addPredicate: @escaping (TracePredicateItem) -> Void,
            table: NSTableView
        ) {
            self.selection = selection
            self.addPredicate = addPredicate
            let newIDs = calls.map(\.id)
            if newIDs != callIDs {
                self.calls = calls
                callIDs = newIDs
                table.reloadData()
            }

            let requestedRow = selection.wrappedValue.flatMap { callIDs.firstIndex(of: $0) } ?? -1
            if table.selectedRow != requestedRow {
                if requestedRow >= 0 {
                    table.selectRowIndexes(IndexSet(integer: requestedRow), byExtendingSelection: false)
                    table.scrollRowToVisible(requestedRow)
                } else {
                    table.deselectAll(nil)
                }
            }
        }

        func numberOfRows(in tableView: NSTableView) -> Int {
            calls.count
        }

        func tableView(
            _ tableView: NSTableView,
            viewFor tableColumn: NSTableColumn?,
            row: Int
        ) -> NSView? {
            guard calls.indices.contains(row), let tableColumn else { return nil }
            let call = calls[row]
            let identifier = tableColumn.identifier
            let cell = tableView.makeView(withIdentifier: identifier, owner: nil) as? CallCellView
                ?? CallCellView(identifier: identifier)
            cell.configure(
                text: ColumnSpecification.text(for: call, column: identifier),
                color: ColumnSpecification.color(for: call, column: identifier),
                monospaced: ColumnSpecification.isMonospaced(identifier)
            )
            return cell
        }

        func tableViewSelectionDidChange(_ notification: Notification) {
            guard let table = notification.object as? NSTableView else { return }
            let row = table.selectedRow
            let newSelection = calls.indices.contains(row) ? calls[row].id : nil
            if selection.wrappedValue != newSelection {
                selection.wrappedValue = newSelection
            }
        }

        func menuNeedsUpdate(_ menu: NSMenu) {
            menu.removeAllItems()
            menuPredicates = []
            guard let table,
                  calls.indices.contains(table.clickedRow) else { return }
            let call = calls[table.clickedRow]

            addMenuItem(
                "This call (PID \(call.processID), #\(call.id.callID))",
                item: .group(TracePredicateGroup(items: [
                    .comparison(.equals(.processID, number(call.processID))),
                    .comparison(.equals(.callID, number(call.id.callID))),
                ])),
                to: menu
            )
            menu.addItem(.separator())
            if let service = call.serviceName {
                addMenuItem(
                    "Service is \(shortened(service))",
                    item: .comparison(.equals(.service, .string(service))),
                    to: menu
                )
            }
            addMenuItem(
                "Function is \(shortened(call.functionName))",
                item: .comparison(.equals(.function, .string(call.functionName))),
                to: menu
            )
            addMenuItem(
                "Role is \(call.role.label)",
                item: .comparison(.equals(.role, .string(call.role.rawValue))),
                to: menu
            )
            addMenuItem(
                "Process ID is \(call.processID)",
                item: .comparison(.equals(.processID, number(call.processID))),
                to: menu
            )
            if let peerProcessID = call.peerProcessID {
                addMenuItem(
                    "Peer process ID is \(peerProcessID)",
                    item: .comparison(.equals(.peerProcessID, number(peerProcessID))),
                    to: menu
                )
            }
            addMenuItem(
                call.isComplete ? "Is a complete pair" : "Is not a complete pair",
                item: .comparison(.equals(.complete, .boolean(call.isComplete))),
                to: menu
            )
        }

        @objc private func addMenuPredicate(_ sender: NSMenuItem) {
            guard menuPredicates.indices.contains(sender.tag) else { return }
            addPredicate(menuPredicates[sender.tag])
        }

        private func addMenuItem(
            _ title: String,
            item: TracePredicateItem,
            to menu: NSMenu
        ) {
            let menuItem = NSMenuItem(
                title: "Add \(title) to Predicate",
                action: #selector(addMenuPredicate(_:)),
                keyEquivalent: ""
            )
            menuItem.target = self
            menuItem.tag = menuPredicates.count
            menuPredicates.append(item)
            menu.addItem(menuItem)
        }

        private func number<T: CustomStringConvertible>(_ value: T) -> TracePredicateLiteral {
            .number(Decimal(string: value.description) ?? 0)
        }

        private func shortened(_ value: String) -> String {
            guard value.count > 64 else { return value }
            return String(value.prefix(61)) + "…"
        }
    }
}

@MainActor
private final class CallCellView: NSTableCellView {
    private let label = NSTextField(labelWithString: "")

    init(identifier: NSUserInterfaceItemIdentifier) {
        super.init(frame: .zero)
        self.identifier = identifier
        label.lineBreakMode = .byTruncatingTail
        label.maximumNumberOfLines = 1
        label.translatesAutoresizingMaskIntoConstraints = false
        addSubview(label)
        NSLayoutConstraint.activate([
            label.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 2),
            label.trailingAnchor.constraint(lessThanOrEqualTo: trailingAnchor, constant: -2),
            label.centerYAnchor.constraint(equalTo: centerYAnchor),
        ])
    }

    required init?(coder: NSCoder) {
        nil
    }

    func configure(
        text: String,
        color: NSColor,
        monospaced: Bool
    ) {
        label.stringValue = text
        label.textColor = color
        label.font = monospaced
            ? NSFont.monospacedSystemFont(ofSize: 11, weight: .regular)
            : NSFont.systemFont(ofSize: 12)
        toolTip = text
    }
}

private struct ColumnSpecification {
    let id: NSUserInterfaceItemIdentifier
    let title: String
    let width: CGFloat
    let minimumWidth: CGFloat
    let maximumWidth: CGFloat
    let resizingMask: NSTableColumn.ResizingOptions

    static let call = ColumnSpecification("call", "#", 65, minimum: 45, maximum: 90)
    static let service = ColumnSpecification("service", "Service", 285, minimum: 140, maximum: 700, flexible: true)
    static let function = ColumnSpecification("function", "Function", 310, minimum: 180, maximum: 700, flexible: true)
    static let type = ColumnSpecification("type", "Type", 90, minimum: 72, maximum: 125)
    static let time = ColumnSpecification("time", "Timestamp", 115, minimum: 100, maximum: 140)
    static let duration = ColumnSpecification("duration", "Duration", 90, minimum: 72, maximum: 115)
    static let peer = ColumnSpecification("peer", "Peer PID", 75, minimum: 65, maximum: 95)
    static let process = ColumnSpecification("pid", "PID", 70, minimum: 60, maximum: 90)
    static let all = [call, service, function, type, time, duration, peer, process]

    init(
        _ rawID: String,
        _ title: String,
        _ width: CGFloat,
        minimum: CGFloat,
        maximum: CGFloat,
        flexible: Bool = false
    ) {
        id = NSUserInterfaceItemIdentifier(rawID)
        self.title = title
        self.width = width
        minimumWidth = minimum
        maximumWidth = maximum
        resizingMask = flexible ? [.autoresizingMask, .userResizingMask] : [.userResizingMask]
    }

    static func text(for call: TraceCall, column: NSUserInterfaceItemIdentifier) -> String {
        switch column {
        case self.call.id: call.id.callID.formatted()
        case service.id: call.serviceName ?? "—"
        case function.id: call.functionName
        case type.id: call.role.label
        case time.id: TraceTimestampFormatter.string(from: call.relativeSeconds)
        case duration.id: call.durationSeconds.map(formatDuration) ?? "—"
        case peer.id: call.peerProcessID?.formatted() ?? "—"
        case process.id: call.processID.formatted()
        default: ""
        }
    }

    static func color(for call: TraceCall, column: NSUserInterfaceItemIdentifier) -> NSColor {
        if column == type.id {
            return roleColor(call)
        }
        if column == self.call.id || column == time.id || column == duration.id {
            return .secondaryLabelColor
        }
        return .labelColor
    }

    static func isMonospaced(_ column: NSUserInterfaceItemIdentifier) -> Bool {
        [call.id, time.id, duration.id, peer.id, process.id].contains(column)
    }

    private static func roleColor(_ call: TraceCall) -> NSColor {
        switch call.role {
        case .request: call.isComplete ? .systemGreen : .systemOrange
        case .response: .systemGreen
        case .incoming: .systemBlue
        case .oneWay: .systemPurple
        case .mach: .secondaryLabelColor
        case .metadata, .diagnostic: .systemGray
        }
    }

    private static func formatDuration(_ seconds: Double) -> String {
        if seconds < 0.001 { return String(format: "%.0f µs", seconds * 1_000_000) }
        if seconds < 1 { return String(format: "%.2f ms", seconds * 1_000) }
        return String(format: "%.3f s", seconds)
    }
}
