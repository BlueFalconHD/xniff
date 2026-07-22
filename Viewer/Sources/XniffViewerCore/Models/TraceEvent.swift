import Foundation

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

public enum XPCObjectKind: UInt16, Sendable, Hashable {
    case connection = 1
    case session = 2
}

public enum XPCObjectLifecycle: UInt16, Sendable, Hashable {
    case observed = 0
    case created = 1
    case cancelled = 2
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
    public let peerAuditToken: [UInt32]?
    public let serviceName: String?
    public let xpcObjectID: UInt64?
    public let xpcObjectKind: XPCObjectKind?
    public let xpcObjectLifecycle: XPCObjectLifecycle?
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
        summary: String,
        peerAuditToken: [UInt32]? = nil,
        xpcObjectID: UInt64? = nil,
        xpcObjectKind: XPCObjectKind? = nil,
        xpcObjectLifecycle: XPCObjectLifecycle? = nil
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
        self.peerAuditToken = peerAuditToken
        self.serviceName = serviceName
        self.xpcObjectID = xpcObjectID
        self.xpcObjectKind = xpcObjectKind
        self.xpcObjectLifecycle = xpcObjectLifecycle
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
            peerProcessID.map(String.init) ?? "",
        ].joined(separator: " ").lowercased()
    }
}
