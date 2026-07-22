import SwiftUI

struct ContentView: View {
    @Bindable var store: TraceStore

    var body: some View {
        VStack(spacing: 0) {
            PredicateEditorView(
                predicate: $store.predicate,
                resultCount: store.visibleCalls.count,
                isFiltering: store.isFiltering
            )
            Divider()

            VSplitView {
                CallTableView(store: store)
                    .frame(minHeight: 120, idealHeight: 390)

                CallInspectorView(
                    document: store.document,
                    call: store.selectedCall
                )
                .frame(minHeight: 140, idealHeight: 420)
            }
        }
        .navigationTitle(store.title)
        .toolbar {
            ToolbarItem(placement: .navigation) {
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
                    Text("Inspect paired XPC calls and decoded message bodies.")
                } actions: {
                    Button("Open Dump…") { store.chooseFile() }
                }
            }
        }
    }
}
