import Foundation

/// Decodes the serialized `EncodingGraph` used by libSwiftXPC's Codable transport.
public enum SwiftXPCCodableGraphDecoder {
    private enum ContainerKind: UInt8 {
        case keyed = 0x0A
        case unkeyed = 0x0B
        case singleValue = 0x0C
    }

    private enum GraphToken {
        case value(TraceValue, tag: UInt8, range: Range<Int>)
        case codingKey(String?, range: Range<Int>)
        case outOfLine(UInt32, range: Range<Int>)
        case metadata(ContainerKind, range: Range<Int>)
        case reference(UInt32, range: Range<Int>)

    }

    private struct ParsedGraph {
        let root: [GraphToken]
        let nodes: [UInt32: [GraphToken]]
    }

    public static func decode(
        _ data: Data,
        outOfLineObjects: [TraceValue] = [],
        codableObjects: [TraceValue] = [],
        sourceOffset: Int = 0
    ) throws -> TraceValue {
        let graph = try parse(data, sourceOffset: sourceOffset)
        let codableReferences = unambiguousCodableReferences(
            in: graph,
            objectCount: codableObjects.count
        )
        return renderContainer(
            graph.root,
            graph: graph,
            outOfLineObjects: outOfLineObjects,
            codableObjects: codableObjects,
            codableReferences: codableReferences,
            visiting: []
        )
    }

    private static func parse(_ data: Data, sourceOffset: Int) throws -> ParsedGraph {
        var reader = BinaryReader(data: data)
        var root: [GraphToken] = []
        var nodes: [UInt32: [GraphToken]] = [:]
        var pendingNodes: Set<UInt32> = []
        var currentNode: UInt32?
        var currentTokens: [GraphToken] = []
        var nextNode: UInt32 = 0

        while reader.remaining > 0 {
            let start = reader.offset
            let tag = try reader.readUInt8()
            let token: GraphToken

            switch tag {
            case 0x00:
                token = .value(.null, tag: tag, range: sourceRange(start..<reader.offset, sourceOffset))
            case 0x01, 0x02:
                token = .value(
                    .bool(tag == 0x01),
                    tag: tag,
                    range: sourceRange(start..<reader.offset, sourceOffset)
                )
            case 0x03:
                token = .value(
                    .string(try readString(&reader)),
                    tag: tag,
                    range: sourceRange(start..<reader.offset, sourceOffset)
                )
            case 0x04:
                token = .value(
                    .double(Double(Float(bitPattern: try reader.readUInt32()))),
                    tag: tag,
                    range: sourceRange(start..<reader.offset, sourceOffset)
                )
            case 0x05:
                token = .value(
                    .double(try reader.readDouble()),
                    tag: tag,
                    range: sourceRange(start..<reader.offset, sourceOffset)
                )
            case 0x06:
                token = .value(
                    .signed(try reader.readInt64()),
                    tag: tag,
                    range: sourceRange(start..<reader.offset, sourceOffset)
                )
            case 0x07:
                token = .value(
                    .signed(Int64(Int8(bitPattern: try reader.readUInt8()))),
                    tag: tag,
                    range: sourceRange(start..<reader.offset, sourceOffset)
                )
            case 0x08:
                token = .value(
                    .signed(Int64(Int16(bitPattern: try reader.readUInt16()))),
                    tag: tag,
                    range: sourceRange(start..<reader.offset, sourceOffset)
                )
            case 0x09:
                token = .value(
                    .signed(Int64(Int32(bitPattern: try reader.readUInt32()))),
                    tag: tag,
                    range: sourceRange(start..<reader.offset, sourceOffset)
                )
            case 0x0A:
                token = .value(
                    .signed(try reader.readInt64()),
                    tag: tag,
                    range: sourceRange(start..<reader.offset, sourceOffset)
                )
            case 0x0B:
                token = .value(
                    .unsigned(try reader.readUInt64()),
                    tag: tag,
                    range: sourceRange(start..<reader.offset, sourceOffset)
                )
            case 0x0C:
                token = .value(
                    .unsigned(UInt64(try reader.readUInt8())),
                    tag: tag,
                    range: sourceRange(start..<reader.offset, sourceOffset)
                )
            case 0x0D:
                token = .value(
                    .unsigned(UInt64(try reader.readUInt16())),
                    tag: tag,
                    range: sourceRange(start..<reader.offset, sourceOffset)
                )
            case 0x0E:
                token = .value(
                    .unsigned(UInt64(try reader.readUInt32())),
                    tag: tag,
                    range: sourceRange(start..<reader.offset, sourceOffset)
                )
            case 0x0F:
                token = .value(
                    .unsigned(try reader.readUInt64()),
                    tag: tag,
                    range: sourceRange(start..<reader.offset, sourceOffset)
                )
            case 0x10:
                token = .codingKey(nil, range: sourceRange(start..<reader.offset, sourceOffset))
            case 0x11:
                token = .codingKey(
                    try readString(&reader),
                    range: sourceRange(start..<reader.offset, sourceOffset)
                )
            case 0x12:
                token = .outOfLine(
                    try reader.readUInt32(),
                    range: sourceRange(start..<reader.offset, sourceOffset)
                )
            case 0x13:
                let rawKind = try reader.readUInt8()
                guard let kind = ContainerKind(rawValue: rawKind) else {
                    throw TraceParseError.invalidFile(
                        String(format: "Invalid Swift XPC container metadata 0x%02X at 0x%X", rawKind, start)
                    )
                }
                token = .metadata(kind, range: sourceRange(start..<reader.offset, sourceOffset))
            case 0x14:
                let identifier = try reader.readUInt32()
                guard nodes[identifier] == nil, pendingNodes.insert(identifier).inserted else {
                    throw TraceParseError.invalidFile("Duplicate Swift XPC container reference \(identifier)")
                }
                token = .reference(
                    identifier,
                    range: sourceRange(start..<reader.offset, sourceOffset)
                )
            case 0x15:
                if let currentNode {
                    nodes[currentNode] = currentTokens
                } else {
                    root = currentTokens
                }
                guard pendingNodes.remove(nextNode) != nil else {
                    throw TraceParseError.invalidFile("Swift XPC graph has an insufficient container transition")
                }
                currentNode = nextNode
                guard nextNode < UInt32.max else {
                    throw TraceParseError.invalidFile("Swift XPC graph exhausted its container identifiers")
                }
                nextNode += 1
                currentTokens = []
                continue
            case 0x16:
                throw TraceParseError.invalidFile("Swift XPC graph ended with a dangling container")
            default:
                throw TraceParseError.unsupported(
                    String(format: "Unsupported Swift XPC graph tag 0x%02X at 0x%X", tag, start)
                )
            }
            currentTokens.append(token)
        }

        if let currentNode {
            nodes[currentNode] = currentTokens
        } else {
            root = currentTokens
        }
        guard pendingNodes.isEmpty else {
            throw TraceParseError.invalidFile("Swift XPC graph contains dangling container references")
        }
        return ParsedGraph(root: root, nodes: nodes)
    }

    private static func readString(_ reader: inout BinaryReader) throws -> String {
        let rawLength = try reader.readUInt64()
        guard rawLength <= UInt64(Int.max - 1) else {
            throw TraceParseError.invalidFile("Swift XPC string length exceeds the platform limit")
        }
        let bytes = try reader.readData(count: Int(rawLength) + 1)
        guard bytes.last == 0 else {
            throw TraceParseError.invalidFile("Swift XPC string is missing its terminator")
        }
        return String(decoding: bytes.dropLast(), as: UTF8.self)
    }

    private static func renderContainer(
        _ tokens: [GraphToken],
        graph: ParsedGraph,
        outOfLineObjects: [TraceValue],
        codableObjects: [TraceValue],
        codableReferences: Set<UInt32>,
        visiting: Set<UInt32>
    ) -> TraceValue {
        let kind = tokens.compactMap { token -> ContainerKind? in
            guard case .metadata(let kind, _) = token else { return nil }
            return kind
        }.first
        let values = tokens.filter {
            if case .metadata = $0 { return false }
            return true
        }

        if kind == .singleValue,
           values.count == 1,
           case .value(.signed(let rawIndex), let tag, let range) = values[0],
           tag == 0x06,
           rawIndex >= 0,
           rawIndex <= Int64(UInt32.max),
           codableReferences.contains(UInt32(rawIndex)) {
            let index = UInt32(rawIndex)
            return sourced(.object(type: "XPCCodableObject reference", fields: [
                TraceField(name: "Index", value: .unsigned(UInt64(index))),
                TraceField(name: "Value", value: codableObjects[Int(index)]),
            ]), range: range)
        }

        switch kind {
        case .keyed:
            var fields: [TraceField] = []
            var index = 0
            while index < values.count {
                guard case .codingKey(let key, _) = values[index] else {
                    fields.append(TraceField(
                        name: "Malformed item \(index)",
                        value: renderToken(
                            values[index],
                            graph: graph,
                            outOfLineObjects: outOfLineObjects,
                            codableObjects: codableObjects,
                            codableReferences: codableReferences,
                            visiting: visiting
                        )
                    ))
                    index += 1
                    continue
                }
                guard index + 1 < values.count else {
                    fields.append(TraceField(name: key ?? "<nil key>", value: .error("Missing keyed value")))
                    break
                }
                fields.append(TraceField(
                    name: key ?? "<nil key>",
                    value: renderToken(
                        values[index + 1],
                        graph: graph,
                        outOfLineObjects: outOfLineObjects,
                        codableObjects: codableObjects,
                        codableReferences: codableReferences,
                        visiting: visiting
                    )
                ))
                index += 2
            }
            return .dictionary(fields)
        case .unkeyed:
            return .array(values.map {
                renderToken(
                    $0,
                    graph: graph,
                    outOfLineObjects: outOfLineObjects,
                    codableObjects: codableObjects,
                    codableReferences: codableReferences,
                    visiting: visiting
                )
            })
        case .singleValue:
            if values.isEmpty { return .null }
            if values.count == 1 {
                return renderToken(
                    values[0],
                    graph: graph,
                    outOfLineObjects: outOfLineObjects,
                    codableObjects: codableObjects,
                    codableReferences: codableReferences,
                    visiting: visiting
                )
            }
            return .array(values.map {
                renderToken(
                    $0,
                    graph: graph,
                    outOfLineObjects: outOfLineObjects,
                    codableObjects: codableObjects,
                    codableReferences: codableReferences,
                    visiting: visiting
                )
            })
        case nil:
            if values.count == 1 {
                return renderToken(
                    values[0],
                    graph: graph,
                    outOfLineObjects: outOfLineObjects,
                    codableObjects: codableObjects,
                    codableReferences: codableReferences,
                    visiting: visiting
                )
            }
            return .array(values.map {
                renderToken(
                    $0,
                    graph: graph,
                    outOfLineObjects: outOfLineObjects,
                    codableObjects: codableObjects,
                    codableReferences: codableReferences,
                    visiting: visiting
                )
            })
        }
    }

    private static func renderToken(
        _ token: GraphToken,
        graph: ParsedGraph,
        outOfLineObjects: [TraceValue],
        codableObjects: [TraceValue],
        codableReferences: Set<UInt32>,
        visiting: Set<UInt32>
    ) -> TraceValue {
        switch token {
        case .value(let value, _, let range):
            return sourced(value, range: range)
        case .codingKey(let key, let range):
            return sourced(.string(key ?? "<nil key>"), range: range)
        case .outOfLine(let index, let range):
            guard Int(index) < outOfLineObjects.count else {
                return sourced(.error("Invalid Swift XPC out-of-line index \(index)"), range: range)
            }
            return sourced(.object(type: "Out-of-line XPC data", fields: [
                TraceField(name: "Index", value: .unsigned(UInt64(index))),
                TraceField(name: "Value", value: outOfLineObjects[Int(index)]),
            ]), range: range)
        case .metadata(let kind, let range):
            return sourced(.string(String(describing: kind)), range: range)
        case .reference(let identifier, let range):
            guard !visiting.contains(identifier) else {
                return sourced(.error("Cyclic Swift XPC container reference \(identifier)"), range: range)
            }
            guard let child = graph.nodes[identifier] else {
                return sourced(.error("Missing Swift XPC container \(identifier)"), range: range)
            }
            var nextVisiting = visiting
            nextVisiting.insert(identifier)
            return renderContainer(
                child,
                graph: graph,
                outOfLineObjects: outOfLineObjects,
                codableObjects: codableObjects,
                codableReferences: codableReferences,
                visiting: nextVisiting
            )
        }
    }

    private static func unambiguousCodableReferences(
        in graph: ParsedGraph,
        objectCount: Int
    ) -> Set<UInt32> {
        guard objectCount > 0 else { return [] }
        var counts: [UInt32: Int] = [:]
        for tokens in Array(graph.nodes.values) + [graph.root] {
            let hasSingleValueMetadata = tokens.contains {
                if case .metadata(.singleValue, _) = $0 { return true }
                return false
            }
            let values = tokens.filter {
                if case .metadata = $0 { return false }
                return true
            }
            guard hasSingleValueMetadata,
                  values.count == 1,
                  case .value(.signed(let rawIndex), let tag, _) = values[0],
                  tag == 0x06,
                  rawIndex >= 0,
                  rawIndex < Int64(objectCount) else {
                continue
            }
            counts[UInt32(rawIndex), default: 0] += 1
        }
        return Set(counts.compactMap { index, count in count == 1 ? index : nil })
    }

    private static func sourceRange(_ range: Range<Int>, _ offset: Int) -> Range<Int> {
        (range.lowerBound + offset)..<(range.upperBound + offset)
    }

    private static func sourced(_ value: TraceValue, range: Range<Int>) -> TraceValue {
        .sourced(range: range, value: value)
    }
}
