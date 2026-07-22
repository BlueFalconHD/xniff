import Foundation
import Testing
@testable import XniffPrint

@Test func parsesPrinterFilters() throws {
    let options = try CommandLineOptions.parse([
        "--pid", "42",
        "--role", "request",
        "--search", "modelmanager",
        "--only-pairs",
        "--raw-xpc",
        "/tmp/capture.xniff",
    ])

    #expect(options.inputURL == URL(fileURLWithPath: "/tmp/capture.xniff"))
    #expect(options.processID == 42)
    #expect(options.role?.rawValue == "request")
    #expect(options.searchText == "modelmanager")
    #expect(options.onlyPairs)
    #expect(options.rawXPC)
}

@Test func rejectsUnknownPrinterOptions() {
    #expect(throws: CommandLineError.unknownOption("--legacy")) {
        try CommandLineOptions.parse(["--legacy", "/tmp/capture.xniff"])
    }
}
