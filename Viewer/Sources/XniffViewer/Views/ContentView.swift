import SwiftUI

struct ContentView: View {
    @Bindable var store: TraceStore

    var body: some View {
        NavigationSplitView {
            filterSidebar
                .navigationSplitViewColumnWidth(min: 150, ideal: 180, max: 230)
        } content: {
            EventTableView(store: store)
                .navigationSplitViewColumnWidth(min: 480, ideal: 650)
        } detail: {
            EventDetailView(store: store, event: store.selectedEvent)
                .navigationSplitViewColumnWidth(min: 350, ideal: 500)
        }
        .navigationTitle(store.title)
        .searchable(text: $store.query, prompt: "Function, service, role, PID, or call ID")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button("Open", systemImage: "folder") { store.chooseFile() }
            }
            if store.isLoading {
                ToolbarItem { ProgressView().controlSize(.small) }
            }
        }
        .overlay {
            if let error = store.errorMessage {
                ContentUnavailableView(
                    "Couldn’t Open Dump",
                    systemImage: "exclamationmark.triangle",
                    description: Text(error)
                )
            } else if store.document == nil && !store.isLoading {
                ContentUnavailableView {
                    Label("Open an xniff Dump", systemImage: "waveform.path.ecg.rectangle")
                } description: {
                    Text("Inspect XPC requests, replies, Mach messages, and archived Foundation objects.")
                } actions: {
                    Button("Open Dump…") { store.chooseFile() }
                }
            }
        }
    }

    private var filterSidebar: some View {
        List(selection: $store.filter) {
            Section("Traffic") {
                ForEach(TraceFilter.allCases) { filter in
                    Label {
                        HStack {
                            Text(filter.label)
                            Spacer()
                            Text(store.count(for: filter), format: .number)
                                .foregroundStyle(.secondary)
                                .monospacedDigit()
                        }
                    } icon: {
                        Image(systemName: filter.systemImage)
                    }
                    .tag(filter)
                }
            }
        }
        .listStyle(.sidebar)
    }
}
