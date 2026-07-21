import Foundation

public enum FoundationXPCEnvelopeDecoder {
    private enum Key {
        static let flags = "f"
        static let outOfLineObjects = "ool"
        static let proxyNumber = "proxynum"
        static let replySignature = "replysig"
        static let root = "root"
        static let sequence = "sequence"
    }

    public static func decode(_ value: TraceValue) -> FoundationXPCEnvelope? {
        guard case .dictionary(let fields) = value.foundationUnwrapped else { return nil }

        let rawFlags = fields.foundationValue(named: Key.flags)?.foundationUnsigned
        let flags = FoundationXPCFlags(rawValue: rawFlags ?? 0)
        let proxyNumber = fields.foundationValue(named: Key.proxyNumber)?.foundationUnsigned
        let sequence = fields.foundationValue(named: Key.sequence)?.foundationUnsigned
        let replySignature = fields.foundationValue(named: Key.replySignature)?.foundationString
        let metadata = fields.filter { $0.name != Key.root && $0.name != Key.outOfLineObjects }

        if flags.contains(.control) {
            return decodeControl(
                flags: flags,
                rawFlags: rawFlags,
                proxyNumber: proxyNumber,
                sequence: sequence,
                replySignature: replySignature,
                metadata: metadata
            )
        }

        guard let root = fields.foundationValue(named: Key.root),
              let archivedRoot = decodedArchive(in: root) else {
            return nil
        }

        var issues: [String] = []
        let outOfLineObjects: [TraceValue]
        if let outOfLineValue = fields.foundationValue(named: Key.outOfLineObjects) {
            if let objects = outOfLineValue.foundationArray {
                outOfLineObjects = objects
            } else {
                outOfLineObjects = []
                issues.append("Out-of-line objects are not encoded as an XPC array")
            }
        } else {
            outOfLineObjects = []
        }
        let decodedRoot = FoundationXPCOutOfLineResolver.resolve(
            archivedRoot,
            objects: outOfLineObjects
        )
        guard let invocation = FoundationXPCInvocation(decodedRoot: decodedRoot) else {
            return nil
        }
        issues.append(contentsOf: invocation.validationIssues)
        issues.append(contentsOf: invocationIssues(
            invocation,
            flags: flags,
            proxyNumber: proxyNumber,
            sequence: sequence,
            replySignature: replySignature
        ))

        let kind: FoundationXPCFrameKind = invocation.kind == .request ? .request : .reply
        return FoundationXPCEnvelope(
            frameKind: kind,
            decodedRoot: decodedRoot,
            invocation: invocation,
            metadata: metadata,
            flags: rawFlags,
            proxyNumber: proxyNumber,
            sequence: sequence,
            replySignature: replySignature,
            outOfLineObjects: outOfLineObjects,
            validationIssues: issues
        )
    }

    private static func decodeControl(
        flags: FoundationXPCFlags,
        rawFlags: UInt64?,
        proxyNumber: UInt64?,
        sequence: UInt64?,
        replySignature: String?,
        metadata: [TraceField]
    ) -> FoundationXPCEnvelope {
        let kind = controlKind(flags)
        var issues: [String] = []
        if !flags.contains(.message) {
            issues.append("Control frame is missing Foundation's message bit")
        }
        if kind == .proxyRelease, proxyNumber == nil {
            issues.append("Proxy release frame has no proxy number")
        }
        if [.progressUpdate, .progressCancellation, .progressPause, .progressResume].contains(kind),
           sequence == nil {
            issues.append("Progress frame has no sequence")
        }
        if flags.contains(.proxyRelease), flags.contains(.progressMessage) {
            issues.append("Control frame combines proxy release and progress flags")
        }
        let progressActions = [
            FoundationXPCFlags.cancelProgress,
            .pauseProgress,
            .resumeProgress,
        ].count(where: flags.contains)
        if progressActions > 1 {
            issues.append("Progress frame requests multiple actions")
        }
        if flags.unknownBits != 0 {
            issues.append(String(format: "Control frame has unknown flag bits 0x%llX", flags.unknownBits))
        }
        return FoundationXPCEnvelope(
            frameKind: kind,
            decodedRoot: nil,
            invocation: nil,
            metadata: metadata,
            flags: rawFlags,
            proxyNumber: proxyNumber,
            sequence: sequence,
            replySignature: replySignature,
            outOfLineObjects: [],
            validationIssues: issues
        )
    }

    private static func invocationIssues(
        _ invocation: FoundationXPCInvocation,
        flags: FoundationXPCFlags,
        proxyNumber: UInt64?,
        sequence: UInt64?,
        replySignature: String?
    ) -> [String] {
        var issues: [String] = []
        if invocation.kind == .request {
            if !flags.contains(.message) {
                issues.append("Request is missing Foundation's message bit")
            }
            if proxyNumber == nil || proxyNumber == 0 {
                issues.append("Request has no exported proxy number")
            }
            if flags.contains(.expectsReply), replySignature == nil {
                issues.append("Request expects a reply but has no reply block signature")
            }
            if flags.contains(.expectsReply), sequence == nil {
                issues.append("Request expects a reply but has no sequence")
            }
            if replySignature != nil, !flags.contains(.expectsReply) {
                issues.append("Request has a reply block signature but does not expect a reply")
            }
        }
        if let replySignature {
            if let parsed = ObjectiveCMethodSignature.parse(replySignature) {
                if parsed.returnType.kind != .void {
                    issues.append("Reply block signature has a non-void return type")
                }
                if parsed.arguments.first?.type.isBlock != true {
                    issues.append("Reply block signature omits its implicit block argument")
                }
            } else {
                issues.append("Reply block signature is malformed")
            }
        }
        if flags.unknownBits != 0 {
            issues.append(String(format: "Invocation has unknown flag bits 0x%llX", flags.unknownBits))
        }
        return issues
    }

    private static func controlKind(_ flags: FoundationXPCFlags) -> FoundationXPCFrameKind {
        if flags.contains(.proxyRelease) { return .proxyRelease }
        guard flags.contains(.progressMessage) else { return .control }
        if flags.contains(.cancelProgress) { return .progressCancellation }
        if flags.contains(.pauseProgress) { return .progressPause }
        if flags.contains(.resumeProgress) { return .progressResume }
        return .progressUpdate
    }

    private static func decodedArchive(in value: TraceValue) -> TraceValue? {
        guard case .data(_, let interpretation) = value.foundationUnwrapped,
              let interpretation,
              case .object(let type, let fields) = interpretation.foundationUnwrapped,
              type.hasPrefix("Binary property list v17") else {
            return nil
        }
        return fields.foundationValue(named: "Decoded value")
    }
}
