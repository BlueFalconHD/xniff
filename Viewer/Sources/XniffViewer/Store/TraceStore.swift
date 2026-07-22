import AppKit
import Foundation
import Observation
import XniffViewerCore

enum TraceFilter: String, CaseIterable, Identifiable, Sendable {
    case all
    case requests
    case unmatchedResponses
    case incoming
    case oneWay
    case mach
    case metadata

    var id: String { rawValue }
    var label: String {
        switch self {
        case .all: "All Traffic"
        case .requests: "Requests"
        case .unmatchedResponses: "Unmatched Responses"
        case .incoming: "Incoming"
        case .oneWay: "One-way"
        case .mach: "Mach"
        case .metadata: "Metadata"
        }
    }

    func includes(_ call: TraceCall) -> Bool {
        switch self {
        case .all: true
        case .requests: call.role == .request
        case .unmatchedResponses: call.role == .response
        case .incoming: call.role == .incoming
        case .oneWay: call.role == .oneWay
        case .mach: call.role == .mach
        case .metadata: [.metadata, .diagnostic].contains(call.role)
        }
    }
}

@MainActor
@Observable
final class TraceStore {
    private(set) var document: TraceDocument?
    private(set) var visibleCalls: [TraceCall] = []
    private(set) var isLoading = false
    private(set) var errorMessage: String?
    var selectedCallID: TraceCallID?
    var query = "" { didSet { scheduleFilter() } }
    var filter: TraceFilter = .all { didSet { scheduleFilter() } }

    @ObservationIgnored private var callsByID: [TraceCallID: TraceCall] = [:]
    @ObservationIgnored private var callCounts: [TraceFilter: Int] = [:]
    @ObservationIgnored private var loadTask: Task<Void, Never>?
    @ObservationIgnored private var filterTask: Task<Void, Never>?

    var selectedCall: TraceCall? {
        selectedCallID.flatMap { callsByID[$0] }
    }

    var title: String {
        document?.url.lastPathComponent ?? "xniff Viewer"
    }

    func count(for filter: TraceFilter) -> Int {
        callCounts[filter, default: 0]
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
        callCounts = [:]

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
                callCounts = Dictionary(uniqueKeysWithValues: TraceFilter.allCases.map { filter in
                    let count = filter == .all
                        ? parsed.calls.count
                        : parsed.calls.lazy.filter(filter.includes).count
                    return (filter, count)
                })
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
        let calls = document?.calls ?? []
        let normalizedQuery = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let selectedFilter = filter

        filterTask = Task {
            try? await Task.sleep(for: delay)
            guard !Task.isCancelled else { return }
            let worker = Task.detached(priority: .userInitiated) {
                try Task.checkCancellation()
                var filtered: [TraceCall] = []
                filtered.reserveCapacity(calls.count)
                for (index, call) in calls.enumerated() {
                    if index.isMultiple(of: 256) { try Task.checkCancellation() }
                    if selectedFilter.includes(call)
                        && (normalizedQuery.isEmpty || call.searchableText.contains(normalizedQuery)) {
                        filtered.append(call)
                    }
                }
                return filtered
            }
            let filtered = try? await withTaskCancellationHandler {
                try await worker.value
            } onCancel: {
                worker.cancel()
            }
            guard let filtered else { return }
            guard !Task.isCancelled else { return }
            visibleCalls = filtered
            if let selectedCallID, !filtered.contains(where: { $0.id == selectedCallID }) {
                self.selectedCallID = filtered.first?.id
            } else if selectedCallID == nil {
                selectedCallID = filtered.first?.id
            }
        }
    }
}
