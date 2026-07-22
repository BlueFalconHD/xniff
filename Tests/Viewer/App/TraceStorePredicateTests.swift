import Testing
import XniffViewerCore
@testable import XniffViewer

@MainActor
@Test func predicateTextKeepsTheLastValidFilterWhileEditing() {
    let store = TraceStore()
    store.predicateText = "pid == 42"

    #expect(store.predicate.text == "pid == 42")
    #expect(store.predicateError == nil)

    store.predicateText = "pid =="

    #expect(store.predicate.text == "pid == 42")
    #expect(store.predicateError != nil)

    store.conjoin(.comparison(.equals(.role, .string("request"))))

    #expect(store.predicateText == #"pid == 42 and role == "request""#)
    #expect(store.predicateError == nil)
}
