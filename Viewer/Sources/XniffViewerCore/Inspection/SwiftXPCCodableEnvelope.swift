import Foundation

public struct SwiftXPCCodableEnvelope: Sendable {
    public let decodedBody: TraceValue
    public let coderVersion: Int64?
    public let isSynchronous: Bool?
    public let outOfLineObjects: [TraceValue]
    public let codableObjects: [TraceValue]
    public let decodingError: String?
}

public enum SwiftXPCCodableEnvelopeDecoder {
    private enum Key {
        static let body = "_CodableBody"
        static let coderVersion = "_CodableCoderVersion"
        static let isSynchronous = "_CodableIsSync"
        static let outOfLine = "_CodableOutOfLine"
        static let codableOutOfLine = "_CodableOutOfLine4CodableObject"
    }

    public static func decode(_ value: TraceValue) -> SwiftXPCCodableEnvelope? {
        guard case .dictionary(let fields) = value.swiftXPCUnwrapped,
              let bodyValue = fields.swiftXPCValue(named: Key.body),
              let (body, sourceOffset) = bodyValue.swiftXPCData else {
            return nil
        }

        let version = fields.swiftXPCValue(named: Key.coderVersion)?.swiftXPCSigned
        let isSynchronous = fields.swiftXPCValue(named: Key.isSynchronous)?.swiftXPCBool
        let outOfLine = fields.swiftXPCValue(named: Key.outOfLine)?.swiftXPCArray ?? []
        let codableOutOfLine = fields.swiftXPCValue(named: Key.codableOutOfLine)?.swiftXPCArray ?? []

        let decodedBody: TraceValue
        let decodingError: String?
        if version != 1 {
            let message = "Unsupported Swift XPC Codable version \(version.map(String.init) ?? "missing")"
            decodedBody = .error(message)
            decodingError = message
        } else {
            do {
                decodedBody = try SwiftXPCCodableGraphDecoder.decode(
                    body,
                    outOfLineObjects: outOfLine,
                    codableObjects: codableOutOfLine,
                    sourceOffset: sourceOffset
                )
                decodingError = nil
            } catch {
                decodedBody = .error(error.localizedDescription)
                decodingError = error.localizedDescription
            }
        }

        return SwiftXPCCodableEnvelope(
            decodedBody: decodedBody,
            coderVersion: version,
            isSynchronous: isSynchronous,
            outOfLineObjects: outOfLine,
            codableObjects: codableOutOfLine,
            decodingError: decodingError
        )
    }
}

private extension Array where Element == TraceField {
    func swiftXPCValue(named name: String) -> TraceValue? {
        first { $0.name == name }?.value
    }
}

private extension TraceValue {
    var swiftXPCUnwrapped: TraceValue {
        if case .sourced(_, let value) = self { return value.swiftXPCUnwrapped }
        return self
    }

    var swiftXPCArray: [TraceValue]? {
        guard case .array(let values) = swiftXPCUnwrapped else { return nil }
        return values
    }

    var swiftXPCBool: Bool? {
        guard case .bool(let value) = swiftXPCUnwrapped else { return nil }
        return value
    }

    var swiftXPCSigned: Int64? {
        switch swiftXPCUnwrapped {
        case .signed(let value): value
        case .unsigned(let value) where value <= UInt64(Int64.max): Int64(value)
        default: nil
        }
    }

    var swiftXPCData: (Data, Int)? {
        switch self {
        case .sourced(let range, let nested):
            guard case .data(let data, _) = nested.swiftXPCUnwrapped else { return nil }
            return (data, range.lowerBound + 8)
        case .data(let data, _):
            return (data, 0)
        default:
            return nil
        }
    }
}
