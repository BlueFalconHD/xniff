import SwiftUI
import XniffViewerCore

enum MessageSide: String, Sendable {
    case request
    case response

    func payloads(in event: TraceEvent) -> [TracePayloadSlice] {
        switch self {
        case .request:
            let preferred: TracePayloadKind = event.role == .incoming ? .event : .message
            let matches = event.payloads.filter { $0.kind == preferred }
            return matches.isEmpty ? event.payloads.filter { $0.kind != .reply } : matches
        case .response:
            let replies = event.payloads.filter { $0.kind == .reply }
            return replies.isEmpty ? event.payloads.filter { $0.kind != .message } : replies
        }
    }
}

private enum MessageTab: String, CaseIterable, Identifiable {
    case headers = "Headers"
    case backtrace = "Backtrace"
    case body = "Body"

    var id: String { rawValue }
}

private enum MessageDecodeState {
    case idle
    case loading
    case loaded([DecodedTracePayload])
}

private struct MessageDecodeIdentity: Hashable {
    let eventID: UInt64?
    let payloadIDs: [UUID]
}

struct MessagePaneView: View {
    let title: String
    let side: MessageSide
    let document: TraceDocument
    let event: TraceEvent?

    @State private var selectedTab: MessageTab = .body
    @State private var decodeState: MessageDecodeState = .idle
    @State private var selectedPayloadID: UUID?
    @State private var highlightedRange: Range<Int>?
    @State private var selectedInspectorID: String?

    var body: some View {
        VStack(spacing: 0) {
            paneHeader
            Divider()
            content
        }
        .task(id: decodeIdentity) {
            await decodePayloads()
        }
        .onChange(of: selectedPayloadID) {
            guard case .loaded(let decoded) = decodeState,
                  let payload = selectedPayload(from: decoded) else { return }
            selectedInspectorID = payload.inspections.first?.id
            highlightedRange = nil
        }
    }

    private var payloads: [TracePayloadSlice] {
        event.map(side.payloads) ?? []
    }

    private var decodeIdentity: MessageDecodeIdentity {
        MessageDecodeIdentity(eventID: event?.id, payloadIDs: payloads.map(\.id))
    }

    private var paneHeader: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                Text(title)
                    .font(.headline)
                Spacer()
                if let event {
                    Text(event.role.label)
                        .font(.caption.weight(.medium))
                        .foregroundStyle(.secondary)
                }
            }
            .padding(.horizontal, 12)
            .frame(height: 34)

            HStack(spacing: 18) {
                ForEach(MessageTab.allCases) { tab in
                    Button {
                        selectedTab = tab
                    } label: {
                        Text(tab.rawValue)
                            .font(.callout.weight(selectedTab == tab ? .semibold : .regular))
                            .foregroundStyle(selectedTab == tab ? .primary : .secondary)
                            .padding(.vertical, 7)
                            .overlay(alignment: .bottom) {
                                if selectedTab == tab {
                                    Rectangle()
                                        .fill(Color.accentColor)
                                        .frame(height: 2)
                                }
                            }
                    }
                    .buttonStyle(.plain)
                }
                Spacer()
            }
            .padding(.horizontal, 12)
        }
    }

    @ViewBuilder
    private var content: some View {
        if let event {
            switch selectedTab {
            case .headers:
                MessageHeadersView(event: event, payloads: payloads)
            case .backtrace:
                BacktraceView(frames: event.backtrace)
            case .body:
                bodyContent
            }
        } else {
            ContentUnavailableView(
                "No \(title)",
                systemImage: side == .request ? "arrow.up.right" : "arrow.down.left",
                description: Text("This call does not contain a captured \(side.rawValue).")
            )
        }
    }

    @ViewBuilder
    private var bodyContent: some View {
        switch decodeState {
        case .idle, .loading:
            ProgressView("Decoding body…")
                .controlSize(.small)
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        case .loaded(let decoded):
            if decoded.isEmpty {
                ContentUnavailableView(
                    "No Body",
                    systemImage: "doc.plaintext",
                    description: Text("No serialized XPC body was captured for this side.")
                )
            } else if let payload = selectedPayload(from: decoded) {
                VStack(spacing: 0) {
                    if decoded.count > 1 {
                        payloadPicker(decoded)
                    }
                    if let inspection = selectedInspection(from: payload) {
                        inspectorPicker(payload.inspections)
                        Divider()
                        BodyInspectionView(
                            payloadID: payload.id,
                            inspection: inspection,
                            parent: payload.parent(of: inspection),
                            data: payload.data,
                            highlightedRange: highlightedRange,
                            viewInParent: viewInParent
                        )
                    }
                }
            }
        }
    }

    private func selectedPayload(from decoded: [DecodedTracePayload]) -> DecodedTracePayload? {
        decoded.first { $0.id == selectedPayloadID } ?? decoded.first
    }

    private func selectedInspection(from payload: DecodedTracePayload) -> BodyInspection? {
        if let selectedInspectorID,
           let selected = payload.inspection(withID: selectedInspectorID) {
            return selected
        }
        return payload.inspections.first
    }

    private func payloadPicker(_ decoded: [DecodedTracePayload]) -> some View {
        Picker("Payload", selection: $selectedPayloadID) {
            ForEach(decoded) { item in
                Text(item.slice.name).tag(Optional(item.id))
            }
        }
        .pickerStyle(.segmented)
        .padding(8)
    }

    private func inspectorPicker(_ inspections: [BodyInspection]) -> some View {
        HStack {
            Picker("View", selection: Binding(
                get: { selectedInspectorID },
                set: { newValue in
                    selectedInspectorID = newValue
                    highlightedRange = nil
                }
            )) {
                ForEach(inspections) { candidate in
                    Text(candidate.name).tag(Optional(candidate.id))
                }
            }
            .frame(minWidth: 150, idealWidth: 180, maxWidth: 220)
            .help("Choose an applicable inspector")
            Spacer()
        }
        .padding(.horizontal, 10)
        .frame(height: 34)
    }

    private func viewInParent(_ parentID: String, range: Range<Int>) {
        selectedInspectorID = parentID
        highlightedRange = range
    }

    private func decodePayloads() async {
        let slices = payloads
        guard !slices.isEmpty else {
            decodeState = .loaded([])
            selectedPayloadID = nil
            highlightedRange = nil
            selectedInspectorID = nil
            return
        }

        decodeState = .loading
        highlightedRange = nil
        selectedInspectorID = nil
        let inputs = slices.map { slice in
            TracePayloadInput(slice: slice, data: document.data(for: slice))
        }
        let decoded = await TracePayloadDecoder.decode(inputs)
        guard !Task.isCancelled else { return }
        decodeState = .loaded(decoded)
        if !decoded.contains(where: { $0.id == selectedPayloadID }) {
            selectedPayloadID = decoded.first?.id
        }
        if let payload = selectedPayload(from: decoded) {
            selectedInspectorID = payload.inspections.first?.id
        }
    }
}
