import Foundation
import XniffViewerCore

struct CommandLineOptions: Equatable {
    let inputURL: URL
    var processID: UInt32?
    var role: TraceRole?
    var searchText: String?
    var onlyPairs = false
    var includeBodies = true
    var rawXPC = false

    static func parse(_ arguments: [String]) throws -> CommandLineOptions {
        var inputPath: String?
        var processID: UInt32?
        var role: TraceRole?
        var searchText: String?
        var onlyPairs = false
        var includeBodies = true
        var rawXPC = false
        var index = 0

        while index < arguments.count {
            let argument = arguments[index]
            switch argument {
            case "-h", "--help":
                throw CommandLineError.helpRequested
            case "--pid":
                let value = try value(after: argument, in: arguments, index: &index)
                guard let parsed = UInt32(value) else {
                    throw CommandLineError.invalidValue(option: argument, value: value)
                }
                processID = parsed
            case "--role":
                let value = try value(after: argument, in: arguments, index: &index)
                guard let parsed = TraceRole(rawValue: value.lowercased()) else {
                    throw CommandLineError.invalidValue(option: argument, value: value)
                }
                role = parsed
            case "--search":
                searchText = try value(after: argument, in: arguments, index: &index)
            case "--only-pairs":
                onlyPairs = true
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
            processID: processID,
            role: role,
            searchText: searchText,
            onlyPairs: onlyPairs,
            includeBodies: includeBodies,
            rawXPC: rawXPC
        )
    }

    func includes(_ call: TraceCall) -> Bool {
        if let processID, call.processID != processID { return false }
        if let role, call.role != role { return false }
        if onlyPairs, call.request == nil || call.response == nil { return false }
        if let searchText,
           !call.searchableText.localizedCaseInsensitiveContains(searchText) {
            return false
        }
        return true
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
    case invalidValue(option: String, value: String)
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
        case .invalidValue(let option, let value):
            "invalid value '\(value)' for \(option)"
        case .unknownOption(let option):
            "unknown option \(option)"
        case .unexpectedArgument(let argument):
            "unexpected argument \(argument)"
        }
    }
}
