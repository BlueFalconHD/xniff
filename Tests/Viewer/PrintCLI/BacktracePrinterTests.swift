import Testing
@testable import XniffViewerCore
@testable import XniffPrint

@Test func rendersSymbolicatedAndRawBacktraceFrames() throws {
    let frames = [
        TraceFrame(
            id: 0,
            programCounter: 0x1018,
            symbolAddress: 0x1000,
            symbolName: "XPCSession.send",
            imagePath: "/usr/lib/swift/libswiftXPC.dylib"
        ),
        TraceFrame(
            id: 1,
            programCounter: 0xABCD,
            symbolAddress: nil,
            symbolName: nil,
            imagePath: nil
        ),
    ]

    let rendered = try #require(BacktracePrinter.render(frames))

    #expect(rendered == """
      backtrace:
        #0 libswiftXPC.dylib XPCSession.send + 0x18
        #1 <unknown> 0xABCD
    """)
}

@Test func omitsEmptyBacktrace() {
    #expect(BacktracePrinter.render([]) == nil)
}
