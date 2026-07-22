import Foundation
import XniffViewerCore

@main
struct XniffPrintCommand {
    static func main() {
        do {
            let options = try CommandLineOptions.parse(Array(CommandLine.arguments.dropFirst()))
            let document = try XniffTraceParser.parse(url: options.inputURL)
            let calls = document.calls.filter(options.includes)
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

      --pid <pid>         Include calls from one process
      --role <role>       Filter by request, response, incoming, one-way, metadata, mach, or diagnostic
      --search <text>     Search function, service, role, summary, and process metadata
      --only-pairs        Require both a request and response
      --raw-xpc           Skip semantic Foundation, Swift Codable, and Core Data views
      --no-body           Print call metadata without decoded bodies
      -h, --help          Show this help
    """
}
