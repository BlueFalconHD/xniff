import SwiftUI

@main
struct XniffViewerApp: App {
    @NSApplicationDelegateAdaptor(XniffApplicationDelegate.self)
    private var applicationDelegate
    @State private var store = TraceStore()

    var body: some Scene {
        WindowGroup {
            ContentView(store: store)
                .frame(minWidth: 1_050, minHeight: 650)
                .onOpenURL { store.open($0) }
                .task {
                    guard store.document == nil,
                          let path = CommandLine.arguments.dropFirst().first else { return }
                    store.open(URL(fileURLWithPath: path))
                }
        }
        .commands {
            CommandGroup(replacing: .newItem) {
                Button("Open Dump…") { store.chooseFile() }
                    .keyboardShortcut("o")
            }
        }
    }
}
