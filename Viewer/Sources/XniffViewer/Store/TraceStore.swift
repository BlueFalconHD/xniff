import AppKit
import Foundation
import Observation
import XniffViewerCore

@MainActor
@Observable
final class TraceStore {
    private(set) var document: TraceDocument?
    private(set) var visibleCalls: [TraceCall] = []
    private(set) var isLoading = false
    private(set) var isFiltering = false
    private(set) var errorMessage: String?
    var selectedCallID: TraceCallID?
    var predicate = TracePredicate.all { didSet { scheduleFilter() } }

    @ObservationIgnored private var callsByID: [TraceCallID: TraceCall] = [:]
    @ObservationIgnored private var bodyIndexCache = TracePredicateBodyIndexCache()
    @ObservationIgnored private var loadTask: Task<Void, Never>?
    @ObservationIgnored private var filterTask: Task<Void, Never>?
    @ObservationIgnored private var filterRevision: UInt64 = 0

    var selectedCall: TraceCall? {
        selectedCallID.flatMap { callsByID[$0] }
    }

    var title: String {
        document?.url.lastPathComponent ?? "xniff Viewer"
    }

    func conjoin(_ item: TracePredicateItem) {
        predicate.conjoin(item)
    }

    func replacePredicate(with text: String) throws {
        predicate = try TracePredicateParser.parse(text)
    }

    func clearPredicate() {
        predicate = .all
    }

    func chooseFile() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = []
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.message = "Open an xniff binary dump"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        open(url)
    }

    func open(_ url: URL) {
        loadTask?.cancel()
        filterTask?.cancel()
        errorMessage = nil
        isLoading = true
        selectedCallID = nil
        document = nil
        visibleCalls = []
        callsByID = [:]
        bodyIndexCache = TracePredicateBodyIndexCache()
        isFiltering = false

        loadTask = Task {
            do {
                let worker = Task.detached(priority: .userInitiated) {
                    try XniffTraceParser.parse(url: url)
                }
                let parsed = try await withTaskCancellationHandler {
                    try await worker.value
                } onCancel: {
                    worker.cancel()
                }
                try Task.checkCancellation()
                document = parsed
                callsByID = Dictionary(uniqueKeysWithValues: parsed.calls.map { ($0.id, $0) })
                isLoading = false
                scheduleFilter(delay: .zero)
            } catch is CancellationError {
                return
            } catch {
                isLoading = false
                errorMessage = error.localizedDescription
            }
        }
    }

    private func scheduleFilter(delay: Duration = .milliseconds(120)) {
        filterTask?.cancel()
        filterRevision &+= 1
        let revision = filterRevision
        guard let document else {
            visibleCalls = []
            isFiltering = false
            return
        }
        let predicate = predicate
        guard predicate.validationError == nil else {
            isFiltering = false
            return
        }
        let cache = bodyIndexCache
        isFiltering = true

        filterTask = Task {
            try? await Task.sleep(for: delay)
            guard !Task.isCancelled else { return }
            let worker = Task.detached(priority: .userInitiated) { () throws -> [TraceCall] in
                try Task.checkCancellation()
                var filtered: [TraceCall] = []
                filtered.reserveCapacity(document.calls.count)
                for (index, call) in document.calls.enumerated() {
                    if index.isMultiple(of: 256) { try Task.checkCancellation() }
                    if try await TracePredicateEvaluator.matches(
                        predicate,
                        call: call,
                        bodyLoader: {
                            await cache.index(for: call, document: document)
                        }
                    ) {
                        filtered.append(call)
                    }
                }
                return filtered
            }
            let filtered: [TraceCall]
            do {
                filtered = try await withTaskCancellationHandler {
                    try await worker.value
                } onCancel: {
                    worker.cancel()
                }
            } catch {
                return
            }
            guard !Task.isCancelled, revision == filterRevision else { return }
            isFiltering = false
            visibleCalls = filtered
            if let selectedCallID, !filtered.contains(where: { $0.id == selectedCallID }) {
                self.selectedCallID = filtered.first?.id
            } else if selectedCallID == nil {
                selectedCallID = filtered.first?.id
            }
        }
    }
}
