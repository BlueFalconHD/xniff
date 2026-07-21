import SwiftUI
import XniffViewerCore

struct EventTableView: View {
    @Bindable var store: TraceStore

    var body: some View {
        Table(store.visibleEvents, selection: $store.selectedEventID) {
            TableColumn("Time") { event in
                Text(String(format: "+%.6f", event.relativeSeconds))
                    .font(.system(.body, design: .monospaced))
                    .foregroundStyle(.secondary)
            }
            .width(min: 90, ideal: 105, max: 125)

            TableColumn("Role") { event in
                RoleLabel(role: event.role)
            }
            .width(min: 75, ideal: 90, max: 110)

            TableColumn("Function") { event in
                Text(event.functionName)
                    .lineLimit(1)
                    .help(event.functionName)
            }
            .width(min: 190, ideal: 260)

            TableColumn("Summary") { event in
                Text(event.summary)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }

            TableColumn("PID") { event in
                Text(event.processID, format: .number)
                    .monospacedDigit()
            }
            .width(65)
        }
        .overlay {
            if store.document != nil && store.visibleEvents.isEmpty && !store.isLoading {
                ContentUnavailableView.search(text: store.query)
            }
        }
    }
}

private struct RoleLabel: View {
    let role: TraceRole

    var body: some View {
        Text(role.label)
            .font(.caption.weight(.medium))
            .foregroundStyle(color)
            .padding(.horizontal, 7)
            .padding(.vertical, 3)
            .background(color.opacity(0.12), in: Capsule())
    }

    private var color: Color {
        switch role {
        case .request: .blue
        case .response: .green
        case .incoming: .orange
        case .oneWay: .purple
        case .mach: .secondary
        case .metadata, .diagnostic: .gray
        }
    }
}
