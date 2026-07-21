import Testing
@testable import XniffViewerCore

private let eventHandlerFunction: UInt32 = 6
private let dictionaryReplyFunction: UInt32 = 8

@Test func doesNotTreatEventHandlerExitAsResponse() {
    let incoming = makeXPCEvent(id: 1, function: eventHandlerFunction, direction: .entry)
    let staleExit = makeXPCEvent(id: 2, function: eventHandlerFunction, direction: .exit)
    let call = TraceCall(
        id: TraceCallID(processID: incoming.processID, callID: 129),
        events: [incoming, staleExit]
    )

    #expect(call.request?.role == .incoming)
    #expect(call.response == nil)
    #expect(!call.isComplete)
}

@Test func pairsIncomingEventWithExplicitDictionaryReply() {
    let incoming = makeXPCEvent(id: 1, function: eventHandlerFunction, direction: .entry)
    let response = makeXPCEvent(id: 2, function: dictionaryReplyFunction, direction: .entry)
    let call = TraceCall(
        id: TraceCallID(processID: incoming.processID, callID: 130),
        events: [incoming, response]
    )

    #expect(call.request?.role == .incoming)
    #expect(call.response?.role == .response)
    #expect(call.isComplete)
}

private func makeXPCEvent(
    id: UInt64,
    function: UInt32,
    direction: TraceDirection
) -> TraceEvent {
    TraceEvent(
        id: id,
        sequence: id,
        processID: 25_177,
        threadID: 1,
        timestampNanoseconds: id * 1_000,
        relativeSeconds: Double(id) / 1_000_000,
        api: .xpc,
        direction: direction,
        function: function,
        functionName: TraceModel.functionName(function),
        role: TraceModel.role(function: function, direction: direction, api: .xpc),
        callID: 129,
        peerProcessID: nil,
        serviceName: nil,
        returnValue: 0,
        arguments: [],
        payloads: [],
        backtrace: [],
        summary: ""
    )
}
