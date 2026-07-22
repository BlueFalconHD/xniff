import Foundation
import Testing
@testable import XniffViewerCore

@Test func parsesAndFormatsNestedPredicates() throws {
    let predicate = try TracePredicateParser.parse(
        #"pid == 42 and (role == request or service matches "^com\\.apple\\.") and duration >= 250ms"#
    )

    #expect(predicate.text == #"pid == 42 and (role == "request" or service matches "^com\\.apple\\.") and duration >= 0.25"#)
    #expect(try TracePredicateParser.parse(predicate.text).text == predicate.text)
}

@Test func preservesNegatedRootGroupPrecedence() throws {
    var predicate = try TracePredicateParser.parse("pid == 42 and role == request")
    predicate.root.isNegated = true

    #expect(predicate.text == #"not (pid == 42 and role == "request")"#)
    #expect(try TracePredicateParser.parse(predicate.text).text == predicate.text)
}

@Test func evaluatesTypedMetadataComparisons() async throws {
    let call = predicateTestCall()
    let predicate = try TracePredicateParser.parse(
        #"pid == 42 and role == request and service contains "model" and duration >= 1ms and complete == true"#
    )

    #expect(try await TracePredicateEvaluator.matches(predicate, call: call))
    #expect(try await TracePredicateEvaluator.matches(
        TracePredicateParser.parse("return.value == 0x2A"),
        call: call
    ))
    #expect(try await !TracePredicateEvaluator.matches(
        TracePredicateParser.parse("peer.pid exists"),
        call: call
    ))
}

@Test func evaluatesInspectorTreePredicates() async throws {
    let call = predicateTestCall()
    let index = TracePredicateBodyIndex(
        inspectorNames: ["Core Data", StandardBodyInspectorID.coreDataXPC],
        entries: [
            TracePredicateTreeEntry(
                side: .request,
                payloadName: "Message",
                inspectorID: StandardBodyInspectorID.coreDataXPC,
                inspectorName: "Core Data",
                path: "$.NSMetadata.store",
                name: "store",
                type: "Metadata",
                value: .string("ScreenTime")
            ),
            TracePredicateTreeEntry(
                side: .response,
                payloadName: "Reply",
                inspectorID: StandardBodyInspectorID.coreDataXPC,
                inspectorName: "Core Data",
                path: "$.Result count",
                name: "Result count",
                value: .number(42)
            ),
        ]
    )
    let predicate = try TracePredicateParser.parse(
        #"inspector == "Core Data" and request.tree contains "NSMetadata.store = ScreenTime" and tree.type == Metadata and tree.number > 40"#
    )

    #expect(try await TracePredicateEvaluator.matches(
        predicate,
        call: call,
        bodyLoader: { index }
    ))
}

@Test func metadataShortCircuitAvoidsInspectorDecoding() async throws {
    let counter = PredicateBodyLoadCounter()
    let predicate = try TracePredicateParser.parse(
        #"pid == 999 or (pid == 998 and tree.value contains "secret")"#
    )

    #expect(try await !TracePredicateEvaluator.matches(
        predicate,
        call: predicateTestCall(),
        bodyLoader: {
            await counter.increment()
            return TracePredicateBodyIndex()
        }
    ))
    #expect(await counter.count == 0)
}

@Test func rejectsInvalidPredicateFieldsAndRegexes() {
    #expect(throws: TracePredicateParseError.self) {
        try TracePredicateParser.parse("unknown.field == 1")
    }
    #expect(throws: TracePredicateParseError.self) {
        try TracePredicateParser.parse(#"service matches "[""#)
    }
}

@Test func validatesVisuallyConstructedPredicates() {
    let predicate = TracePredicate(root: TracePredicateGroup(items: [
        .comparison(TracePredicateComparison(
            field: .service,
            operation: .matches,
            value: .string("[")
        )),
    ]))

    #expect(predicate.validationError != nil)
}

private actor PredicateBodyLoadCounter {
    private(set) var count = 0

    func increment() {
        count += 1
    }
}

private func predicateTestCall() -> TraceCall {
    let request = predicateTestEvent(
        id: 1,
        sequence: 10,
        relativeSeconds: 0.25,
        direction: .entry,
        role: .request,
        returnValue: 0
    )
    let response = predicateTestEvent(
        id: 2,
        sequence: 11,
        relativeSeconds: 0.252,
        direction: .exit,
        role: .response,
        returnValue: 42
    )
    return TraceCall(
        id: TraceCallID(processID: 42, callID: 7),
        events: [request, response]
    )
}

private func predicateTestEvent(
    id: UInt64,
    sequence: UInt64,
    relativeSeconds: Double,
    direction: TraceDirection,
    role: TraceRole,
    returnValue: UInt64
) -> TraceEvent {
    TraceEvent(
        id: id,
        sequence: sequence,
        processID: 42,
        threadID: 9,
        timestampNanoseconds: id * 1_000,
        relativeSeconds: relativeSeconds,
        api: .xpc,
        direction: direction,
        function: 3,
        functionName: "xpc_connection_send_message_with_reply_sync",
        role: role,
        callID: 7,
        peerProcessID: nil,
        serviceName: "com.apple.modelmanager",
        returnValue: returnValue,
        arguments: [1, 2],
        payloads: [],
        backtrace: [],
        summary: "Model request"
    )
}
