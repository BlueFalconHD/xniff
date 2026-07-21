import Foundation

public struct FoundationXPCFlags: OptionSet, Sendable {
    public let rawValue: UInt64

    public init(rawValue: UInt64) {
        self.rawValue = rawValue
    }

    // These bits are consumed by Foundation's message_handler_message and set by
    // the invocation, proxy-desist, and progress send paths.
    public static let message = FoundationXPCFlags(rawValue: 0x0000_0001)
    public static let control = FoundationXPCFlags(rawValue: 0x0000_0004)
    public static let proxyRelease = FoundationXPCFlags(rawValue: 0x0000_0008)
    public static let progressMessage = FoundationXPCFlags(rawValue: 0x0000_0010)
    public static let expectsReply = FoundationXPCFlags(rawValue: 0x0000_0020)
    public static let carriesProgress = FoundationXPCFlags(rawValue: 0x0000_0040)
    public static let returnsProgress = FoundationXPCFlags(rawValue: 0x0000_0080)
    public static let cancelProgress = FoundationXPCFlags(rawValue: 0x0001_0000)
    public static let pauseProgress = FoundationXPCFlags(rawValue: 0x0002_0000)
    public static let resumeProgress = FoundationXPCFlags(rawValue: 0x0004_0000)

    public static let knownMask: FoundationXPCFlags = [
        .message,
        .control,
        .proxyRelease,
        .progressMessage,
        .expectsReply,
        .carriesProgress,
        .returnsProgress,
        .cancelProgress,
        .pauseProgress,
        .resumeProgress,
    ]

    public var unknownBits: UInt64 { rawValue & ~Self.knownMask.rawValue }

    public var labels: [String] {
        var result: [String] = []
        let values: [(FoundationXPCFlags, String)] = [
            (.message, "message"),
            (.control, "control"),
            (.proxyRelease, "proxy release"),
            (.progressMessage, "progress"),
            (.expectsReply, "expects reply"),
            (.carriesProgress, "carries progress"),
            (.returnsProgress, "returns progress"),
            (.cancelProgress, "cancel"),
            (.pauseProgress, "pause"),
            (.resumeProgress, "resume"),
        ]
        for (flag, label) in values where contains(flag) {
            result.append(label)
        }
        if unknownBits != 0 {
            result.append(String(format: "unknown 0x%llX", unknownBits))
        }
        return result
    }
}

public enum FoundationXPCFrameKind: String, Sendable {
    case request
    case reply
    case proxyRelease
    case progressUpdate
    case progressCancellation
    case progressPause
    case progressResume
    case control
    case invalidInvocation

    public var label: String {
        switch self {
        case .request: "Request"
        case .reply: "Reply"
        case .proxyRelease: "Proxy release"
        case .progressUpdate: "Progress update"
        case .progressCancellation: "Progress cancellation"
        case .progressPause: "Progress pause"
        case .progressResume: "Progress resume"
        case .control: "Control"
        case .invalidInvocation: "Invalid invocation"
        }
    }
}
