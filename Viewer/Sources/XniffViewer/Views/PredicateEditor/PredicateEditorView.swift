import AppKit
import SwiftUI
import XniffViewerCore

struct PredicateEditorView: View {
    @Binding var predicate: TracePredicate
    let resultCount: Int
    let isFiltering: Bool

    @State private var isTextEditorPresented = false

    var body: some View {
        VStack(spacing: 0) {
            HStack(spacing: 10) {
                Label("Predicate", systemImage: "line.3.horizontal.decrease.circle")
                    .font(.headline)

                if let validationError = predicate.validationError {
                    Label("Invalid predicate", systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.red)
                        .help(validationError)
                } else if isFiltering {
                    ProgressView()
                        .controlSize(.small)
                    Text("Filtering…")
                        .foregroundStyle(.secondary)
                } else {
                    Text(predicate.isEmpty ? "All calls" : "\(resultCount.formatted()) matches")
                        .foregroundStyle(.secondary)
                }

                Spacer()

                Button("Copy", systemImage: "doc.on.doc") {
                    copyPredicate()
                }
                .disabled(predicate.isEmpty)
                .help("Copy the text predicate")

                Button("Text", systemImage: "text.alignleft") {
                    isTextEditorPresented = true
                }
                .help("Edit or paste the text representation")

                Button("Clear", systemImage: "xmark.circle") {
                    predicate = .all
                }
                .disabled(predicate.isEmpty)
            }
            .buttonStyle(.borderless)
            .padding(.horizontal, 12)
            .frame(height: 36)

            Divider()

            ScrollView(.vertical) {
                PredicateGroupEditor(group: $predicate.root, isRoot: true)
                    .padding(10)
            }
            .frame(maxHeight: 210)
        }
        .background(.bar)
        .sheet(isPresented: $isTextEditorPresented) {
            PredicateTextEditor(predicate: $predicate)
        }
    }

    private func copyPredicate() {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(predicate.text, forType: .string)
    }
}

private struct PredicateTextEditor: View {
    @Environment(\.dismiss) private var dismiss
    @Binding var predicate: TracePredicate

    @State private var text: String
    @State private var errorMessage: String?

    init(predicate: Binding<TracePredicate>) {
        _predicate = predicate
        _text = State(initialValue: predicate.wrappedValue.text)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Text Predicate")
                .font(.title2.weight(.semibold))

            Text("Use and, or, not, parentheses, comparisons, contains, matches, and exists. Times accept s, ms, µs, and ns.")
                .foregroundStyle(.secondary)

            TextEditor(text: $text)
                .font(.system(.body, design: .monospaced))
                .frame(minHeight: 140)
                .padding(6)
                .background(.background, in: RoundedRectangle(cornerRadius: 6))
                .overlay {
                    RoundedRectangle(cornerRadius: 6)
                        .stroke(.separator)
                }

            if let errorMessage {
                Label(errorMessage, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
            }

            Text(#"Example: service contains "model" and (role == request or duration >= 25ms)"#)
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)

            HStack {
                Button("Copy") {
                    let pasteboard = NSPasteboard.general
                    pasteboard.clearContents()
                    pasteboard.setString(text, forType: .string)
                }
                Spacer()
                Button("Cancel", role: .cancel) { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Apply") { apply() }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(minWidth: 650, minHeight: 320)
    }

    private func apply() {
        do {
            predicate = try TracePredicateParser.parse(text)
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
