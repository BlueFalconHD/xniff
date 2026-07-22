import Foundation
import XniffViewerCore

@main
struct XniffPrintCommand {
    static func main() async {
        do {
            let options = try CommandLineOptions.parse(Array(CommandLine.arguments.dropFirst()))
            let document = try XniffTraceParser.parse(url: options.inputURL)
            let cache = TracePredicateBodyIndexCache()
            var calls: [TraceCall] = []
            for call in document.calls {
                if try await TracePredicateEvaluator.matches(
                    options.predicate,
                    call: call,
                    bodyLoader: {
                        await cache.index(for: call, document: document)
                    }
                ) {
                    calls.append(call)
                }
            }
            for (index, call) in calls.enumerated() {
                if index > 0 { print() }
                print(TraceCallPrinter.render(call, document: document, options: options))
            }
            FileHandle.standardError.write(
                Data("calls=\(calls.count) events=\(document.events.count)\n".utf8)
            )
        } catch CommandLineError.helpRequested {
            print(usage)
        } catch {
            FileHandle.standardError.write(Data("xniff-print: \(error.localizedDescription)\n".utf8))
            FileHandle.standardError.write(Data("\(usage)\n".utf8))
            exit(2)
        }
    }

    private static let usage = """
    Usage: xniff-print [options] <capture.xniff>

      -p, --predicate <expression>
                          Filter with the shared predicate language; repeat to AND expressions
      --raw-xpc           Skip semantic Foundation, Swift Codable, and Core Data views
      --no-body           Print call metadata without decoded bodies
      -h, --help          Show this help

    Examples:
      --predicate 'pid == 42 and role == "request" and complete == true'
      --predicate 'service contains "model" or duration >= 25ms'
      --predicate 'request.tree contains "NSMetadata.store = ScreenTime"'
    """
}
