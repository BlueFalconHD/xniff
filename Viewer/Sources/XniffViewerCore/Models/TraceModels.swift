import Foundation

public indirect enum TraceValue: Sendable, Equatable {
    case null
    case bool(Bool)
    case signed(Int64)
    case unsigned(UInt64)
    case double(Double)
    case string(String)
    case data(Data, interpretation: TraceValue?)
    case array([TraceValue])
    case dictionary([TraceField])
    case object(type: String, fields: [TraceField])
    case reference(Int)
    case sourced(range: Range<Int>, value: TraceValue)
    case error(String)

    public var summary: String {
        switch self {
        case .null: "null"
        case .bool(let value): value ? "true" : "false"
        case .signed(let value): String(value)
        case .unsigned(let value): String(value)
        case .double(let value): String(value)
        case .string(let value): value
        case .data(let value, _): "Data (\(value.count.formatted()) bytes)"
        case .array(let values): "Array (\(values.count.formatted()) items)"
        case .dictionary(let fields): "Dictionary (\(fields.count.formatted()) keys)"
        case .object(let type, _): type
        case .reference(let index): "reference \(index)"
        case .sourced(_, let value): value.summary
        case .error(let message): message
        }
    }
}

public struct TraceField: Sendable, Equatable, Identifiable {
    public let id: UUID
    public let name: String
    public let value: TraceValue

    public init(name: String, value: TraceValue, id: UUID = UUID()) {
        self.id = id
        self.name = name
        self.value = value
    }
}

public enum TraceAPI: UInt16, Sendable, Hashable {
    case machMessage = 1
    case machMessage2 = 2
    case xpc = 3
    case diagnostic = 4

    public var label: String {
        switch self {
        case .machMessage: "mach_msg"
        case .machMessage2: "mach_msg2"
        case .xpc: "XPC"
        case .diagnostic: "Diagnostic"
        }
    }
}

public enum TraceDirection: UInt16, Sendable, Hashable {
    case entry = 0
    case exit = 1

    public var label: String { self == .entry ? "entry" : "exit" }
}

public enum TraceRole: String, CaseIterable, Sendable, Hashable, Identifiable {
    case request
    case response
    case incoming
    case oneWay = "one-way"
    case metadata
    case mach
    case diagnostic

    public var id: String { rawValue }
    public var label: String {
        switch self {
        case .oneWay: "One-way"
        default: rawValue.capitalized
        }
    }
}

public enum TracePayloadKind: UInt8, Sendable, Hashable {
    case unknown = 0
    case message = 1
    case reply = 2
    case event = 3

    public var label: String {
        switch self {
        case .unknown: "Payload"
        case .message: "Message"
        case .reply: "Reply"
        case .event: "Event"
        }
    }
}

public struct TracePayloadSlice: Sendable, Hashable, Identifiable {
    public let id: UUID
    public let kind: TracePayloadKind
    public let format: UInt8
    public let originalLength: Int
    public let isTruncated: Bool
    public let range: Range<Int>

    public var name: String { kind.label }

    public init(
        kind: TracePayloadKind,
        format: UInt8,
        originalLength: Int,
        isTruncated: Bool,
        range: Range<Int>,
        id: UUID = UUID()
    ) {
        self.id = id
        self.kind = kind
        self.format = format
        self.originalLength = originalLength
        self.isTruncated = isTruncated
        self.range = range
    }
}

public struct TraceFrame: Sendable, Hashable, Identifiable {
    public let id: Int
    public let programCounter: UInt64
    public let symbolAddress: UInt64?
    public let symbolName: String?
    public let imagePath: String?

    public var offset: UInt64? {
        guard let symbolAddress, programCounter >= symbolAddress else { return nil }
        return programCounter - symbolAddress
    }
}

public struct TraceEvent: Sendable, Identifiable, Hashable {
    public let id: UInt64
    public let sequence: UInt64
    public let processID: UInt32
    public let threadID: UInt32
    public let timestampNanoseconds: UInt64
    public let relativeSeconds: Double
    public let api: TraceAPI
    public let direction: TraceDirection
    public let function: UInt32
    public let functionName: String
    public let role: TraceRole
    public let callID: UInt64?
    public let peerProcessID: UInt32?
    public let serviceName: String?
    public let returnValue: UInt64
    public let arguments: [UInt64]
    public let payloads: [TracePayloadSlice]
    public let backtrace: [TraceFrame]
    public let summary: String
    public let searchableText: String

    public init(
        id: UInt64,
        sequence: UInt64,
        processID: UInt32,
        threadID: UInt32,
        timestampNanoseconds: UInt64,
        relativeSeconds: Double,
        api: TraceAPI,
        direction: TraceDirection,
        function: UInt32,
        functionName: String,
        role: TraceRole,
        callID: UInt64?,
        peerProcessID: UInt32?,
        serviceName: String?,
        returnValue: UInt64,
        arguments: [UInt64],
        payloads: [TracePayloadSlice],
        backtrace: [TraceFrame],
        summary: String
    ) {
        self.id = id
        self.sequence = sequence
        self.processID = processID
        self.threadID = threadID
        self.timestampNanoseconds = timestampNanoseconds
        self.relativeSeconds = relativeSeconds
        self.api = api
        self.direction = direction
        self.function = function
        self.functionName = functionName
        self.role = role
        self.callID = callID
        self.peerProcessID = peerProcessID
        self.serviceName = serviceName
        self.returnValue = returnValue
        self.arguments = arguments
        self.payloads = payloads
        self.backtrace = backtrace
        self.summary = summary
        self.searchableText = [
            functionName,
            role.rawValue,
            serviceName ?? "",
            summary,
            callID.map(String.init) ?? "",
            String(processID),
        ].joined(separator: " ").lowercased()
    }
}

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
            return traffic
        }
        if events.first?.api != .xpc || events.contains(where: { $0.role == .metadata }) {
            return events.first { $0.direction == .entry } ?? events.first
        }
        return nil
    }

    public var response: TraceEvent? {
        events.first { $0.role == .response }
            ?? events.last { $0.direction == .exit && $0.id != request?.id }
    }

    public var primaryEvent: TraceEvent { request ?? response ?? events[0] }
    public var role: TraceRole { request?.role ?? response?.role ?? primaryEvent.role }
    public var serviceName: String? {
        events.lazy.compactMap(\.serviceName).first
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

public enum TraceModel {
    public static func functionName(_ function: UInt32) -> String {
        switch function {
        case 1: "xpc_connection_create"
        case 2: "xpc_pipe_routine"
        case 3: "xpc_connection_send_message"
        case 4: "xpc_connection_send_message_with_reply"
        case 5: "xpc_connection_send_message_with_reply_sync"
        case 6: "_xpc_connection_call_event_handler"
        case 7: "_xpc_connection_check_in"
        case 8: "xpc_dictionary_send_reply"
        case 9: "xpc_session_send_message"
        case 10: "xpc_session_send_message_with_reply_async"
        case 11: "xpc_session_send_message_with_reply_sync"
        default: "xpc_function_\(function)"
        }
    }

    public static func role(function: UInt32, direction: TraceDirection, api: TraceAPI) -> TraceRole {
        guard api == .xpc else {
            return api == .diagnostic ? .diagnostic : .mach
        }
        switch function {
        case 2, 4, 5, 10, 11:
            return direction == .entry ? .request : .response
        case 8:
            return .response
        case 6:
            return .incoming
        case 3, 9:
            return .oneWay
        default:
            return .metadata
        }
    }
}
