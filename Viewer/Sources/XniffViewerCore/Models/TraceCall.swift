import Foundation

public struct TraceCallID: Sendable, Hashable {
    public let processID: UInt32
    public let callID: UInt64

    public init(processID: UInt32, callID: UInt64) {
        self.processID = processID
        self.callID = callID
    }
}

public struct TraceCall: Sendable, Identifiable, Hashable {
    public let id: TraceCallID
    public let events: [TraceEvent]

    public init(id: TraceCallID, events: [TraceEvent]) {
        self.id = id
        self.events = events.sorted { $0.sequence < $1.sequence }
    }

    public var request: TraceEvent? {
        if let traffic = events.first(where: { [.request, .incoming, .oneWay].contains($0.role) }) {
            return mergingCallMetadata(into: traffic)
        }
        if events.first?.api != .xpc || events.contains(where: { $0.role == .metadata }) {
            return (events.first { $0.direction == .entry } ?? events.first)
                .map(mergingCallMetadata)
        }
        return nil
    }

    public var response: TraceEvent? {
        if request.map(isSessionEvent) == true,
           let sessionResponse = events.first(where: { $0.role == .response && isSessionEvent($0) }) {
            return mergingCallMetadata(into: sessionResponse)
        }
        if let response = events.first(where: { $0.role == .response }) {
            return mergingCallMetadata(into: response)
        }
        if let request, [.incoming, .oneWay].contains(request.role) {
            return nil
        }
        return events.last { $0.direction == .exit && $0.id != request?.id }
            .map(mergingCallMetadata)
    }

    public var primaryEvent: TraceEvent { request ?? response ?? events[0] }
    public var role: TraceRole { request?.role ?? response?.role ?? primaryEvent.role }
    public var serviceName: String? {
        events.lazy.compactMap(\.serviceName).first
    }
    public var peerProcessID: UInt32? {
        events.lazy.compactMap(\.peerProcessID).first
    }
    public var functionName: String { primaryEvent.functionName }
    public var processID: UInt32 { id.processID }
    public var relativeSeconds: Double { events.first?.relativeSeconds ?? 0 }
    public var durationSeconds: Double? {
        guard let first = events.first, let last = events.last, first.id != last.id else { return nil }
        return max(0, last.relativeSeconds - first.relativeSeconds)
    }
    public var isComplete: Bool { response != nil }
    public var searchableText: String {
        events.map(\.searchableText).joined(separator: " ")
    }

    private func isSessionEvent(_ event: TraceEvent) -> Bool {
        event.api == .xpc && (9...11).contains(event.function)
    }

    private func mergingCallMetadata(into event: TraceEvent) -> TraceEvent {
        let peerProcessID = event.peerProcessID ?? events.lazy.compactMap(\.peerProcessID).first
        let serviceName = event.serviceName ?? events.lazy.compactMap(\.serviceName).first
        guard peerProcessID != event.peerProcessID || serviceName != event.serviceName else {
            return event
        }
        return TraceEvent(
            id: event.id,
            sequence: event.sequence,
            processID: event.processID,
            threadID: event.threadID,
            timestampNanoseconds: event.timestampNanoseconds,
            relativeSeconds: event.relativeSeconds,
            api: event.api,
            direction: event.direction,
            function: event.function,
            functionName: event.functionName,
            role: event.role,
            callID: event.callID,
            peerProcessID: peerProcessID,
            serviceName: serviceName,
            returnValue: event.returnValue,
            arguments: event.arguments,
            payloads: event.payloads,
            backtrace: event.backtrace,
            summary: event.summary,
            machMessage: event.machMessage,
            peerAuditToken: event.peerAuditToken,
            xpcObjectID: event.xpcObjectID,
            xpcObjectKind: event.xpcObjectKind,
            xpcObjectLifecycle: event.xpcObjectLifecycle
        )
    }
}

public struct TraceDocument: Sendable {
    public let url: URL
    public let data: Data
    public let events: [TraceEvent]
    public let calls: [TraceCall]

    public init(url: URL, data: Data, events: [TraceEvent], calls: [TraceCall]) {
        self.url = url
        self.data = data
        self.events = events
        self.calls = calls
    }

    public func data(for payload: TracePayloadSlice) -> Data {
        data.subdata(in: payload.range)
    }
}
