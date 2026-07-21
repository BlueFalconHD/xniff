import AppKit
import Foundation
import Observation
import XniffViewerCore

enum TraceFilter: String, CaseIterable, Identifiable, Sendable {
    case all
    case requests
    case incoming
    case oneWay
    case mach
    case metadata

    var id: String { rawValue }
    var label: String {
        switch self {
        case .all: "All Traffic"
        case .requests: "Requests"
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
    @ObservationIgnored private var loadTask: Task<Void, Never>?
    @ObservationIgnored private var filterTask: Task<Void, Never>?

    var selectedCall: TraceCall? {
        selectedCallID.flatMap { callsByID[$0] }
    }

    var title: String {
        document?.url.lastPathComponent ?? "xniff Viewer"
    }

    func count(for filter: TraceFilter) -> Int {
        guard let calls = document?.calls else { return 0 }
        return filter == .all ? calls.count : calls.lazy.filter(filter.includes).count
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

        loadTask = Task {
            do {
                let parsed = try await Task.detached(priority: .userInitiated) {
                    try XniffTraceParser.parse(url: url)
                }.value
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
        let calls = document?.calls ?? []
        let normalizedQuery = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let selectedFilter = filter

        filterTask = Task {
            try? await Task.sleep(for: delay)
            guard !Task.isCancelled else { return }
            let filtered = await Task.detached(priority: .userInitiated) {
                calls.filter { call in
                    selectedFilter.includes(call)
                        && (normalizedQuery.isEmpty || call.searchableText.contains(normalizedQuery))
                }
            }.value
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
