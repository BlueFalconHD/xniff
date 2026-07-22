import Testing
@testable import XniffViewerCore

private let eventHandlerFunction: UInt32 = 6
private let dictionaryReplyFunction: UInt32 = 8
private let asyncReplyFunction: UInt32 = 4
private let asyncSessionReplyFunction: UInt32 = 10

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

@Test func representsAnUnmatchedInternalAsyncReplyAsResponseOnly() {
    let response = makeXPCEvent(id: 3, function: asyncReplyFunction, direction: .exit)
    let call = TraceCall(
        id: TraceCallID(processID: response.processID, callID: 131),
        events: [response]
    )

    #expect(call.request == nil)
    #expect(call.response?.role == .response)
    #expect(call.primaryEvent.id == response.id)
    #expect(call.role == .response)
}

@Test func coalescesSessionAndConnectionLayersWithoutLosingMetadata() throws {
    let swiftFrame = TraceFrame(
        id: 0,
        programCounter: 0x1000,
        symbolAddress: 0x1000,
        symbolName: "XPCSession.send",
        imagePath: "/usr/lib/swift/libswiftXPC.dylib"
    )
    let sessionRequest = makeXPCEvent(
        id: 10,
        function: asyncSessionReplyFunction,
        direction: .entry,
        backtrace: [swiftFrame]
    )
    let connectionRequest = makeXPCEvent(
        id: 11,
        function: asyncReplyFunction,
        direction: .entry,
        serviceName: "com.apple.modelmanager"
    )
    let connectionResponse = makeXPCEvent(
        id: 12,
        function: asyncReplyFunction,
        direction: .exit,
        serviceName: "com.apple.modelmanager"
    )
    let sessionResponse = makeXPCEvent(
        id: 13,
        function: asyncSessionReplyFunction,
        direction: .exit,
        backtrace: [swiftFrame]
    )
    let call = TraceCall(
        id: TraceCallID(processID: sessionRequest.processID, callID: 129),
        events: [sessionRequest, connectionRequest, connectionResponse, sessionResponse]
    )

    #expect(call.functionName == "xpc_session_send_message_with_reply_async")
    #expect(call.request?.id == sessionRequest.id)
    #expect(call.request?.backtrace == [swiftFrame])
    #expect(call.request?.serviceName == "com.apple.modelmanager")
    #expect(call.response?.id == sessionResponse.id)
    #expect(call.response?.backtrace == [swiftFrame])
    #expect(call.response?.serviceName == "com.apple.modelmanager")
    #expect(call.serviceName == "com.apple.modelmanager")
    #expect(call.isComplete)
}

private func makeXPCEvent(
    id: UInt64,
    function: UInt32,
    direction: TraceDirection,
    serviceName: String? = nil,
    backtrace: [TraceFrame] = []
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
        serviceName: serviceName,
        returnValue: 0,
        arguments: [],
        payloads: [],
        backtrace: backtrace,
        summary: ""
    )
}
