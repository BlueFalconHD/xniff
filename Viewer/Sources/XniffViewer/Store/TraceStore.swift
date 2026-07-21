import AppKit
import Foundation
import Observation
import XniffViewerCore

enum TraceFilter: String, CaseIterable, Identifiable, Sendable {
    case all
    case requests
    case responses
    case incoming
    case oneWay
    case mach

    var id: String { rawValue }
    var label: String {
        switch self {
        case .all: "All Events"
        case .requests: "Requests"
        case .responses: "Responses"
        case .incoming: "Incoming"
        case .oneWay: "One-way"
        case .mach: "Mach"
        }
    }

    var systemImage: String {
        switch self {
        case .all: "list.bullet.rectangle"
        case .requests: "arrow.up.right"
        case .responses: "arrow.down.left"
        case .incoming: "tray.and.arrow.down"
        case .oneWay: "arrow.right"
        case .mach: "cpu"
        }
    }

    func includes(_ event: TraceEvent) -> Bool {
        switch self {
        case .all: true
        case .requests: event.role == .request
        case .responses: event.role == .response
        case .incoming: event.role == .incoming
        case .oneWay: event.role == .oneWay
        case .mach: event.role == .mach
        }
    }
}

private struct PayloadCacheKey: Hashable {
    let eventID: UInt64
    let payloadID: UUID
}

@MainActor
@Observable
final class TraceStore {
    private(set) var document: TraceDocument?
    private(set) var visibleEvents: [TraceEvent] = []
    private(set) var isLoading = false
    private(set) var errorMessage: String?
    private(set) var decodeRevision = 0
    var selectedEventID: UInt64?
    var query = "" { didSet { scheduleFilter() } }
    var filter: TraceFilter = .all { didSet { scheduleFilter() } }

    @ObservationIgnored private var eventsByID: [UInt64: TraceEvent] = [:]
    @ObservationIgnored private var eventsByCallID: [UInt64: [TraceEvent]] = [:]
    @ObservationIgnored private var filterCounts: [TraceFilter: Int] = [:]
    @ObservationIgnored private var decodedPayloads: [PayloadCacheKey: TraceValue] = [:]
    @ObservationIgnored private var loadTask: Task<Void, Never>?
    @ObservationIgnored private var filterTask: Task<Void, Never>?
    @ObservationIgnored private var decodeTasks: [PayloadCacheKey: Task<Void, Never>] = [:]

    var selectedEvent: TraceEvent? {
        selectedEventID.flatMap { eventsByID[$0] }
    }

    var title: String {
        document?.url.lastPathComponent ?? "xniff Viewer"
    }

    func count(for filter: TraceFilter) -> Int {
        filterCounts[filter, default: 0]
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
        errorMessage = nil
        isLoading = true
        selectedEventID = nil
        document = nil
        visibleEvents = []
        eventsByID = [:]
        eventsByCallID = [:]
        filterCounts = [:]
        decodedPayloads = [:]

        loadTask = Task {
            do {
                let parsed = try await Task.detached(priority: .userInitiated) {
                    try XniffTraceParser.parse(url: url)
                }.value
                guard !Task.isCancelled else { return }
                document = parsed
                eventsByID = Dictionary(uniqueKeysWithValues: parsed.events.map { ($0.id, $0) })
                eventsByCallID = Dictionary(grouping: parsed.events.compactMap { event in
                    event.callID.map { ($0, event) }
                }, by: { $0.0 }).mapValues { $0.map(\.1) }
                filterCounts = Dictionary(uniqueKeysWithValues: TraceFilter.allCases.map { filter in
                    (filter, filter == .all ? parsed.events.count : parsed.events.lazy.filter(filter.includes).count)
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

    func decodedValue(event: TraceEvent, payload: TracePayloadSlice) -> TraceValue? {
        decodedPayloads[PayloadCacheKey(eventID: event.id, payloadID: payload.id)]
    }

    func relatedEvents(to event: TraceEvent) -> [TraceEvent] {
        guard let callID = event.callID else { return [] }
        return eventsByCallID[callID, default: []].filter { $0.id != event.id }
    }

    func decodePayloads(for event: TraceEvent) {
        guard let document else { return }
        for payload in event.payloads {
            let key = PayloadCacheKey(eventID: event.id, payloadID: payload.id)
            guard decodedPayloads[key] == nil, decodeTasks[key] == nil else { continue }
            let bytes = document.data(for: payload)
            decodeTasks[key] = Task {
                let value = await Task.detached(priority: .userInitiated) {
                    EmbeddedPayloadDecoder.decode(bytes, format: payload.format)
                }.value
                guard !Task.isCancelled else { return }
                decodedPayloads[key] = value
                decodeRevision &+= 1
                decodeTasks[key] = nil
            }
        }
    }

    private func scheduleFilter(delay: Duration = .milliseconds(120)) {
        filterTask?.cancel()
        filterTask = Task {
            try? await Task.sleep(for: delay)
            guard !Task.isCancelled else { return }
            guard let events = document?.events else {
                visibleEvents = []
                return
            }
            let normalizedQuery = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            let selectedFilter = filter
            let filtered = await Task.detached(priority: .userInitiated) {
                events.filter { event in
                    selectedFilter.includes(event)
                        && (normalizedQuery.isEmpty || event.searchableText.contains(normalizedQuery))
                }
            }.value
            guard !Task.isCancelled else { return }
            visibleEvents = filtered
            if let selectedEventID, !filtered.contains(where: { $0.id == selectedEventID }) {
                self.selectedEventID = filtered.first?.id
            } else if selectedEventID == nil {
                selectedEventID = filtered.first?.id
            }
        }
    }
}
