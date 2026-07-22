import Foundation

public struct TracePredicateParseError: LocalizedError, Equatable {
    public let message: String
    public let offset: Int

    public init(_ message: String, offset: Int) {
        self.message = message
        self.offset = offset
    }

    public var errorDescription: String? {
        "\(message) at column \(offset + 1)"
    }
}

public enum TracePredicateParser {
    public static func parse(_ source: String) throws -> TracePredicate {
        var parser = try Parser(source: source)
        return try parser.parse()
    }
}

private struct Parser {
    fileprivate enum Token: Equatable {
        case word(String, Int)
        case string(String, Int)
        case symbol(String, Int)
        case leftParenthesis(Int)
        case rightParenthesis(Int)
        case end(Int)

        var offset: Int {
            switch self {
            case .word(_, let offset), .string(_, let offset), .symbol(_, let offset),
                 .leftParenthesis(let offset), .rightParenthesis(let offset), .end(let offset):
                offset
            }
        }
    }

    private let tokens: [Token]
    private var index = 0

    init(source: String) throws {
        var lexer = Lexer(source: source)
        self.tokens = try lexer.tokens()
    }

    mutating func parse() throws -> TracePredicate {
        if case .end = current { return .all }
        let item = try parseOr()
        guard case .end = current else {
            throw error("Unexpected token")
        }
        if case .group(let group) = item, !group.isNegated {
            return TracePredicate(root: group)
        }
        return TracePredicate(root: TracePredicateGroup(items: [item]))
    }

    private var current: Token { tokens[index] }

    private mutating func advance() { index += 1 }

    private func error(_ message: String, at token: Token? = nil) -> TracePredicateParseError {
        TracePredicateParseError(message, offset: (token ?? current).offset)
    }

    private mutating func parseOr() throws -> TracePredicateItem {
        var result = try parseAnd()
        while consumeWord("or") || consumeSymbol("||") {
            result = combine(result, try parseAnd(), with: .or)
        }
        return result
    }

    private mutating func parseAnd() throws -> TracePredicateItem {
        var result = try parseNot()
        while consumeWord("and") || consumeSymbol("&&") {
            result = combine(result, try parseNot(), with: .and)
        }
        return result
    }

    private mutating func parseNot() throws -> TracePredicateItem {
        var isNegated = false
        while consumeWord("not") || consumeSymbol("!") {
            isNegated.toggle()
        }
        var item = try parsePrimary()
        if isNegated { item.isNegated.toggle() }
        return item
    }

    private mutating func parsePrimary() throws -> TracePredicateItem {
        if case .leftParenthesis = current {
            advance()
            let item = try parseOr()
            guard case .rightParenthesis = current else {
                throw error("Expected ')'")
            }
            advance()
            if case .group = item { return item }
            return .group(TracePredicateGroup(items: [item]))
        }
        return .comparison(try parseComparison())
    }

    private mutating func parseComparison() throws -> TracePredicateComparison {
        if case .string(let value, _) = current {
            advance()
            return TracePredicateComparison(field: .any, operation: .contains, value: .string(value))
        }

        guard case .word(let fieldName, let fieldOffset) = current else {
            throw error("Expected a field name or parenthesized predicate")
        }
        advance()

        guard let field = TracePredicateField.recognized(fieldName) else {
            if isExpressionBoundary(current) {
                return TracePredicateComparison(
                    field: .any,
                    operation: .contains,
                    value: .string(fieldName)
                )
            }
            throw TracePredicateParseError("Unknown field '\(fieldName)'", offset: fieldOffset)
        }

        let predicateOperator = try parseOperator()
        var value = TracePredicateLiteral.defaultValue(for: field.valueKind)
        if predicateOperator.requiresValue {
            value = try parseLiteral(for: field)
        }

        if predicateOperator == .matches,
           case .string(let pattern) = value {
            do {
                _ = try NSRegularExpression(pattern: pattern)
            } catch {
                throw self.error("Invalid regular expression")
            }
        }

        let supported = TracePredicateOperator.supported(for: field.valueKind)
        guard supported.contains(predicateOperator) else {
            throw error("Operator is not valid for \(field.rawValue)")
        }
        return TracePredicateComparison(
            field: field,
            operation: predicateOperator,
            value: value
        )
    }

    private mutating func parseOperator() throws -> TracePredicateOperator {
        if case .symbol(let symbol, _) = current {
            advance()
            switch symbol {
            case "=", "==": return .equals
            case "!=": return .notEquals
            case "<": return .lessThan
            case "<=": return .lessThanOrEqual
            case ">": return .greaterThan
            case ">=": return .greaterThanOrEqual
            default: throw error("Unknown operator '\(symbol)'")
            }
        }

        let negated = consumeWord("not")
        guard case .word(let keyword, let offset) = current else {
            throw error("Expected a comparison operator")
        }
        advance()
        switch keyword.lowercased() {
        case "contains": return negated ? .notContains : .contains
        case "beginswith", "startswith":
            guard !negated else { throw TracePredicateParseError("Use 'not field beginswith'", offset: offset) }
            return .beginsWith
        case "endswith":
            guard !negated else { throw TracePredicateParseError("Use 'not field endswith'", offset: offset) }
            return .endsWith
        case "matches":
            guard !negated else { throw TracePredicateParseError("Use 'not field matches'", offset: offset) }
            return .matches
        case "exists": return negated ? .notExists : .exists
        default: throw TracePredicateParseError("Unknown operator '\(keyword)'", offset: offset)
        }
    }

    private mutating func parseLiteral(for field: TracePredicateField) throws -> TracePredicateLiteral {
        let token = current
        let raw: String
        switch token {
        case .string(let value, _), .word(let value, _): raw = value
        default: throw error("Expected a comparison value")
        }
        advance()

        switch field.valueKind {
        case .string:
            return .string(raw)
        case .number:
            return .number(try parseNumber(raw, field: field, token: token))
        case .boolean:
            switch raw.lowercased() {
            case "true", "yes", "1": return .boolean(true)
            case "false", "no", "0": return .boolean(false)
            default: throw error("Expected true or false", at: token)
            }
        }
    }

    private func parseNumber(
        _ rawValue: String,
        field: TracePredicateField,
        token: Token
    ) throws -> Decimal {
        let lowercased = rawValue.lowercased()
        if lowercased.hasPrefix("0x"),
           let value = UInt64(lowercased.dropFirst(2), radix: 16),
           let decimal = Decimal(string: String(value)) {
            return decimal
        }

        var numberText = lowercased
        var multiplier = Decimal(1)
        if [.timestamp, .duration].contains(field) {
            if numberText.hasSuffix("ms") {
                numberText.removeLast(2)
                multiplier = Decimal(string: "0.001") ?? 0
            } else if numberText.hasSuffix("us") || numberText.hasSuffix("µs") {
                numberText.removeLast(2)
                multiplier = Decimal(string: "0.000001") ?? 0
            } else if numberText.hasSuffix("ns") {
                numberText.removeLast(2)
                multiplier = Decimal(string: "0.000000001") ?? 0
            } else if numberText.hasSuffix("s") {
                numberText.removeLast()
            }
        }
        guard let number = Decimal(string: numberText, locale: Locale(identifier: "en_US_POSIX")) else {
            throw error("Expected a number", at: token)
        }
        return number * multiplier
    }

    private func combine(
        _ lhs: TracePredicateItem,
        _ rhs: TracePredicateItem,
        with conjunction: TracePredicateConjunction
    ) -> TracePredicateItem {
        if case .group(var group) = lhs,
           group.conjunction == conjunction,
           !group.isNegated {
            group.items.append(rhs)
            return .group(group)
        }
        return .group(TracePredicateGroup(conjunction: conjunction, items: [lhs, rhs]))
    }

    private mutating func consumeWord(_ expected: String) -> Bool {
        guard case .word(let word, _) = current,
              word.caseInsensitiveCompare(expected) == .orderedSame else { return false }
        advance()
        return true
    }

    private mutating func consumeSymbol(_ expected: String) -> Bool {
        guard case .symbol(let symbol, _) = current, symbol == expected else { return false }
        advance()
        return true
    }

    private func isExpressionBoundary(_ token: Token) -> Bool {
        switch token {
        case .end, .rightParenthesis: true
        case .word(let word, _): ["and", "or"].contains(word.lowercased())
        case .symbol(let symbol, _): ["&&", "||"].contains(symbol)
        default: false
        }
    }
}

private struct Lexer {
    private let characters: [Character]
    private var index = 0

    init(source: String) {
        self.characters = Array(source)
    }

    mutating func tokens() throws -> [Parser.Token] {
        var result: [Parser.Token] = []
        while true {
            skipWhitespace()
            guard index < characters.count else {
                result.append(.end(index))
                return result
            }
            let offset = index
            switch characters[index] {
            case "(":
                index += 1
                result.append(.leftParenthesis(offset))
            case ")":
                index += 1
                result.append(.rightParenthesis(offset))
            case "\"":
                result.append(.string(try readString(start: offset), offset))
            case "=", "!", "<", ">", "&", "|":
                result.append(.symbol(readSymbol(), offset))
            default:
                result.append(.word(readWord(), offset))
            }
        }
    }

    private mutating func skipWhitespace() {
        while index < characters.count, characters[index].isWhitespace { index += 1 }
    }

    private mutating func readString(start: Int) throws -> String {
        index += 1
        var result = ""
        while index < characters.count {
            let character = characters[index]
            index += 1
            if character == "\"" { return result }
            if character == "\\" {
                guard index < characters.count else {
                    throw TracePredicateParseError("Unterminated escape sequence", offset: index - 1)
                }
                let escaped = characters[index]
                index += 1
                switch escaped {
                case "n": result.append("\n")
                case "t": result.append("\t")
                case "r": result.append("\r")
                case "\"": result.append("\"")
                case "\\": result.append("\\")
                default: result.append(escaped)
                }
            } else {
                result.append(character)
            }
        }
        throw TracePredicateParseError("Unterminated string", offset: start)
    }

    private mutating func readSymbol() -> String {
        let first = characters[index]
        index += 1
        guard index < characters.count else { return String(first) }
        let pair = String([first, characters[index]])
        if ["==", "!=", "<=", ">=", "&&", "||"].contains(pair) {
            index += 1
            return pair
        }
        return String(first)
    }

    private mutating func readWord() -> String {
        let start = index
        while index < characters.count {
            let character = characters[index]
            if character.isWhitespace || "()=!<>&|\"".contains(character) { break }
            index += 1
        }
        return String(characters[start..<index])
    }
}
