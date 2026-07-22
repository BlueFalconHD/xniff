import Foundation
import Testing
@testable import XniffViewerCore

private let requestInvocationArchive = Data(nsxpcHex: """
    62706c6973743137a04d00000000000000
    7f111568616e646c65526571756573743a7265706c793a00
    7f110f76333240303a38403136403f323400
    a04d00000000000000787061796c6f616400e0
    """)

private let replyInvocationArchive = Data(nsxpcHex: """
    62706c6973743137a03f00000000000000e0
    7f111d763234403f3040224e5344617461223840224e534572726f7222313600
    a03f00000000000000736f6b00e0
    """)

@Test func parsesObservedNSXPCRequestInvocationLayout() throws {
    let envelope = try #require(FoundationXPCEnvelopeDecoder.decode(expandedEnvelope(
        archive: requestInvocationArchive,
        fields: [
            TraceField(name: "f", value: .unsigned(0x21)),
            TraceField(name: "proxynum", value: .unsigned(1)),
            TraceField(name: "sequence", value: .unsigned(42)),
            TraceField(name: "replysig", value: .string(#"v24@?0@"NSData"8@"NSError"16"#)),
        ]
    )))
    let invocation = try #require(envelope.invocation)

    #expect(envelope.frameKind == .request)
    #expect(invocation.kind == .request)
    #expect(invocation.selector == "handleRequest:reply:")
    #expect(invocation.methodSignature?.returnType.displayName == "void")
    #expect(invocation.arguments.map { $0.type?.displayName } == ["object", "block"])
    #expect(invocation.arguments[0].value.foundationString == "payload")
    #expect(invocation.arguments[1].value.foundationIsNull)
    #expect(envelope.replyObjectTypes == ["NSData", "NSError"])
    #expect(envelope.flagSet == [.message, .expectsReply])
    #expect(envelope.validationIssues.isEmpty)
}

@Test func parsesObservedNSXPCReplyInvocationLayout() throws {
    let envelope = try #require(FoundationXPCEnvelopeDecoder.decode(expandedEnvelope(
        archive: replyInvocationArchive
    )))
    let invocation = try #require(envelope.invocation)

    #expect(envelope.frameKind == .reply)
    #expect(invocation.kind == .reply)
    #expect(invocation.selector == nil)
    #expect(invocation.arguments.map { $0.type?.objectClassName } == ["NSData", "NSError"])
    #expect(invocation.arguments[0].value.foundationString == "ok")
    #expect(invocation.arguments[1].value.foundationIsNull)
    #expect(envelope.flags == nil)
    #expect(envelope.validationIssues.isEmpty)
}

@Test func foundationInspectorOmitsInvocationDetailsAlreadyShownInTree() throws {
    let body = expandedEnvelope(
        archive: requestInvocationArchive,
        fields: [
            TraceField(name: "f", value: .unsigned(0x21)),
            TraceField(name: "proxynum", value: .unsigned(1)),
            TraceField(name: "sequence", value: .unsigned(42)),
            TraceField(name: "replysig", value: .string(#"v8@?0"#)),
        ]
    )
    let raw = BodyInspection(
        id: StandardBodyInspectorID.rawXPC,
        name: "Raw XPC",
        priority: 0,
        parentID: StandardBodyInspectorID.hex,
        content: .tree(body)
    )
    let context = BodyInspectorContext(
        originalBody: body,
        originalData: Data(),
        inspections: [StandardBodyInspectorID.rawXPC: raw]
    )
    let inspection = try #require(FoundationNSXPCBodyInspector().inspect(context))

    #expect(inspection.tree?.summary == "NSXPC request")
    #expect(inspection.details.contains { $0.label == "Frame" && $0.value == "Request" })
    #expect(!inspection.details.contains { $0.label == "Operation" })
    #expect(!inspection.details.contains { $0.label == "Invocation signature" })
    #expect(!inspection.details.contains { $0.label == "Return type" })
    #expect(!inspection.details.contains { $0.label == "Argument types" })
    #expect(inspection.details.contains {
        $0.label == "Flags" && $0.value.contains("expects reply")
    })
}

@Test func decodesNSXPCControlFramesWithoutInvocationRoots() throws {
    let cases: [(UInt64, FoundationXPCFrameKind)] = [
        (0x0D, .proxyRelease),
        (0x15, .progressUpdate),
        (0x10015, .progressCancellation),
        (0x20015, .progressPause),
        (0x40015, .progressResume),
    ]

    for (flags, expectedKind) in cases {
        let value = TraceValue.dictionary([
            TraceField(name: "f", value: .unsigned(flags)),
            TraceField(name: "proxynum", value: .unsigned(7)),
            TraceField(name: "sequence", value: .unsigned(9)),
        ])
        let envelope = try #require(FoundationXPCEnvelopeDecoder.decode(value))
        #expect(envelope.frameKind == expectedKind)
        #expect(envelope.invocation == nil)
        #expect(envelope.validationIssues.isEmpty)
    }
}

@Test func resolvesNSXPCOutOfLineObjectReferences() throws {
    let root = TraceValue.array([
        .string("sendEndpoint:"),
        .string("v24@0:8@16"),
        .array([
            .object(type: "OS_xpc_endpoint", fields: [
                TraceField(name: "$xpc", value: .signed(0))
            ])
        ]),
    ])
    let endpoint = TraceValue.object(type: "XPC endpoint", fields: [
        TraceField(name: "port", value: .unsigned(123))
    ])
    let value = expandedEnvelope(root: root, fields: [
        TraceField(name: "f", value: .unsigned(1)),
        TraceField(name: "ool", value: .array([endpoint])),
    ])
    let envelope = try #require(FoundationXPCEnvelopeDecoder.decode(value))
    let argument = try #require(envelope.invocation?.arguments.first?.value)
    guard case .object(_, let fields) = argument.foundationUnwrapped else {
        Issue.record("Expected the archived XPC wrapper object")
        return
    }

    #expect(fields.foundationValue(named: "Out-of-line index")?.foundationUnsigned == 0)
    #expect(fields.foundationValue(named: "Out-of-line value")?.foundationUnwrapped == endpoint)
    #expect(envelope.outOfLineObjects == [endpoint])
}

@Test func parsesCompleteObjectiveCMethodTypeGrammar() throws {
    let signature = try #require(ObjectiveCMethodSignature.parse(
        #"v64@0:8r^{Thing=i}16[4f]24@"NSObject<NSCopying><NSSecureCoding>"40"#
    ))
    let wireArguments = signature.wireArguments(for: .request)

    #expect(signature.frameLength == 64)
    #expect(signature.returnType.kind == .void)
    #expect(wireArguments.map(\.offset) == [16, 24, 40])
    #expect(wireArguments[0].type.displayName == "const struct Thing *")
    #expect(wireArguments[1].type.displayName == "float[4]")
    #expect(wireArguments[2].type.objectClassName == "NSObject")
    #expect(wireArguments[2].type.displayName == "NSObject<NSCopying><NSSecureCoding> *")
    #expect(ObjectiveCMethodSignature.parse(#"v16@0@"unterminated"#) == nil)
}

@Test func rejectsNonNSXPCPropertyListRoots() {
    let value = TraceValue.dictionary([
        TraceField(name: "root", value: .data(Data([0]), interpretation: .object(
            type: "Binary property list v0 at 0x0",
            fields: [TraceField(name: "Decoded value", value: .array([]))]
        )))
    ])
    #expect(FoundationXPCEnvelopeDecoder.decode(value) == nil)
}

private func expandedEnvelope(
    archive: Data,
    fields: [TraceField] = []
) -> TraceValue {
    EmbeddedPayloadDecoder.expandEmbeddedData(.dictionary(
        fields + [TraceField(name: "root", value: .data(archive, interpretation: nil))]
    ))
}

private func expandedEnvelope(
    root: TraceValue,
    fields: [TraceField] = []
) -> TraceValue {
    .dictionary(fields + [
        TraceField(name: "root", value: .data(Data([0]), interpretation: .object(
            type: "Binary property list v17 at 0x0",
            fields: [TraceField(name: "Decoded value", value: root)]
        )))
    ])
}

private extension Data {
    init(nsxpcHex: String) {
        self.init()
        let compact = nsxpcHex.filter { !$0.isWhitespace }
        var index = compact.startIndex
        while index < compact.endIndex {
            let next = compact.index(index, offsetBy: 2)
            append(UInt8(compact[index..<next], radix: 16)!)
            index = next
        }
    }
}
