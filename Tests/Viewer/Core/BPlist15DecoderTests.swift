import Foundation
import Testing

@testable import XniffViewerCore

@Test func decodesObservedPowerLogBPlist15WithTransportPadding() throws {
    var data = Data(
        hex: """
            62706C6973743135
            136100000000000080
            1200000000
            D4
            78636C69656E744944
            756576656E74
            7C70726F636573732D6E616D65
            7973686F756C644C6F67
            10B9
            7953706F746C69676874
            7F10906950686F6E65204D6972726F72696E67
            74506F7374
            """)
    data.append(Data(repeating: 0, count: 187))

    #expect(data.count == 284)
    let value = try BPlist15Decoder.decode(data, sourceOffset: 0x500)
    let fields = try #require(value.dictionaryFields)

    #expect(fields.map(\.name) == ["clientID", "event", "process-name", "shouldLog"])
    #expect(fields[0].value.unwrapped == .signed(57))
    #expect(fields[1].value.unwrapped == .string("Spotlight"))
    #expect(fields[2].value.unwrapped == .string("iPhone Mirroring"))
    #expect(fields[3].value.unwrapped == .string("Post"))
}

@Test func expandsBPlist15DataAsAnEmbeddedPropertyList() throws {
    let data = makeBPlist15(root: Data(hex: "A3107F0809"))
    let expanded = EmbeddedPayloadDecoder.expandEmbeddedData(.data(data, interpretation: nil))

    guard case .data(_, let interpretation) = expanded else {
        Issue.record("Expected expanded Data")
        return
    }
    #expect(
        interpretation?.recursiveStrings.contains { $0.hasPrefix("Binary property list v15") }
            == true)
    #expect(interpretation?.recursiveValues.contains(.signed(-1)) == true)
    #expect(interpretation?.recursiveValues.contains(.bool(false)) == true)
    #expect(interpretation?.recursiveValues.contains(.bool(true)) == true)
}

@Test func rejectsBPlist15WhoseDeclaredLengthExceedsItsData() {
    var data = makeBPlist15(root: Data([0x00]))
    data.replaceSubrange(
        9..<17,
        with: withUnsafeBytes(of: (UInt64(100) ^ (UInt64(1) << 63)).littleEndian) {
            Data($0)
        })

    #expect(throws: (any Error).self) {
        try BPlist15Decoder.decode(data)
    }
}

private func makeBPlist15(root: Data) -> Data {
    var data = Data("bplist15".utf8)
    data.append(0x13)
    var encodedLength = (UInt64(22 + root.count) ^ (UInt64(1) << 63)).littleEndian
    withUnsafeBytes(of: &encodedLength) { data.append(contentsOf: $0) }
    data.append(contentsOf: [0x12, 0, 0, 0, 0])
    data.append(root)
    return data
}

extension Data {
    fileprivate init(hex: String) {
        self.init()
        let compact = hex.filter { !$0.isWhitespace }
        var index = compact.startIndex
        while index < compact.endIndex {
            let next = compact.index(index, offsetBy: 2)
            append(UInt8(compact[index..<next], radix: 16)!)
            index = next
        }
    }
}

extension TraceValue {
    fileprivate var unwrapped: TraceValue {
        if case .sourced(_, let nested) = self { return nested.unwrapped }
        return self
    }

    fileprivate var dictionaryFields: [TraceField]? {
        if case .dictionary(let fields) = unwrapped { return fields }
        return nil
    }

    fileprivate var recursiveStrings: Set<String> {
        switch self {
        case .string(let value): [value]
        case .array(let values): values.reduce(into: []) { $0.formUnion($1.recursiveStrings) }
        case .dictionary(let fields):
            fields.reduce(into: Set(fields.map(\.name))) { $0.formUnion($1.value.recursiveStrings) }
        case .object(let type, let fields):
            fields.reduce(into: Set([type] + fields.map(\.name))) {
                $0.formUnion($1.value.recursiveStrings)
            }
        case .data(_, let interpretation): interpretation?.recursiveStrings ?? []
        case .sourced(_, let value): value.recursiveStrings
        default: []
        }
    }

    fileprivate var recursiveValues: [TraceValue] {
        switch self {
        case .array(let values): values.flatMap(\.recursiveValues)
        case .dictionary(let fields), .object(_, let fields):
            fields.flatMap { $0.value.recursiveValues }
        case .data(_, let interpretation): interpretation?.recursiveValues ?? [self]
        case .sourced(_, let value): value.recursiveValues
        default: [self]
        }
    }
}
