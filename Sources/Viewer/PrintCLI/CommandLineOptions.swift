import Foundation
import XniffViewerCore

struct CommandLineOptions: Equatable {
    let inputURL: URL
    var predicate = TracePredicate.all
    var includeBodies = true
    var rawXPC = false

    static func parse(_ arguments: [String]) throws -> CommandLineOptions {
        var inputPath: String?
        var predicate = TracePredicate.all
        var includeBodies = true
        var rawXPC = false
        var index = 0

        while index < arguments.count {
            let argument = arguments[index]
            switch argument {
            case "-h", "--help":
                throw CommandLineError.helpRequested
            case "-p", "--predicate":
                let value = try value(after: argument, in: arguments, index: &index)
                do {
                    let parsed = try TracePredicateParser.parse(value)
                    if predicate.isEmpty {
                        predicate = parsed
                    } else if !parsed.isEmpty {
                        predicate.conjoin(.group(parsed.root))
                    }
                } catch {
                    throw CommandLineError.invalidPredicate(error.localizedDescription)
                }
            case "--no-body":
                includeBodies = false
            case "--raw-xpc":
                rawXPC = true
            default:
                if argument.hasPrefix("-") {
                    throw CommandLineError.unknownOption(argument)
                }
                guard inputPath == nil else {
                    throw CommandLineError.unexpectedArgument(argument)
                }
                inputPath = argument
            }
            index += 1
        }

        guard let inputPath else { throw CommandLineError.missingInput }
        return CommandLineOptions(
            inputURL: URL(fileURLWithPath: inputPath),
            predicate: predicate,
            includeBodies: includeBodies,
            rawXPC: rawXPC
        )
    }

    private static func value(
        after option: String,
        in arguments: [String],
        index: inout Int
    ) throws -> String {
        index += 1
        guard index < arguments.count else {
            throw CommandLineError.missingValue(option)
        }
        return arguments[index]
    }
}

enum CommandLineError: LocalizedError, Equatable {
    case helpRequested
    case missingInput
    case missingValue(String)
    case invalidPredicate(String)
    case unknownOption(String)
    case unexpectedArgument(String)

    var errorDescription: String? {
        switch self {
        case .helpRequested:
            nil
        case .missingInput:
            "missing capture path"
        case .missingValue(let option):
            "missing value for \(option)"
        case .invalidPredicate(let message):
            "invalid predicate: \(message)"
        case .unknownOption(let option):
            "unknown option \(option)"
        case .unexpectedArgument(let argument):
            "unexpected argument \(argument)"
        }
    }
}
