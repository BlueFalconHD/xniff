import Foundation
import Testing
@testable import XniffPrint

@Test func parsesPrinterFilters() throws {
    let options = try CommandLineOptions.parse([
        "--predicate", "pid == 42 and role == request",
        "-p", #"service contains "modelmanager" and complete == true"#,
        "--raw-xpc",
        "/tmp/capture.xniff",
    ])

    #expect(options.inputURL == URL(fileURLWithPath: "/tmp/capture.xniff"))
    #expect(options.predicate.text == #"pid == 42 and role == "request" and (service contains "modelmanager" and complete == true)"#)
    #expect(options.rawXPC)
}

@Test func rejectsUnknownPrinterOptions() {
    #expect(throws: CommandLineError.unknownOption("--legacy")) {
        try CommandLineOptions.parse(["--legacy", "/tmp/capture.xniff"])
    }
}

@Test func rejectsLegacyPrinterFilters() {
    #expect(throws: CommandLineError.unknownOption("--pid")) {
        try CommandLineOptions.parse(["--pid", "42", "/tmp/capture.xniff"])
    }
}

@Test func rejectsInvalidPrinterPredicates() {
    #expect(throws: CommandLineError.self) {
        try CommandLineOptions.parse([
            "--predicate", "duration contains fast",
            "/tmp/capture.xniff",
        ])
    }
}
