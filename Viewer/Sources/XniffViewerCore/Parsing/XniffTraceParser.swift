import Foundation

public enum XniffTraceParser {
    private static let fileMagic: UInt32 = 0x584e4246
    private static let fileVersion: UInt16 = 2
    private static let recordVersion: UInt16 = 1
    private static let maximumRecordLength = 64 * 1024 * 1024

    public static func parse(url: URL) throws -> TraceDocument {
        let data = try Data(contentsOf: url, options: [.mappedIfSafe])
        return try parse(data: data, sourceURL: url)
    }

    public static func parse(data: Data, sourceURL: URL = URL(fileURLWithPath: "capture.xniff")) throws -> TraceDocument {
        var reader = BinaryReader(data: data)
        guard data.count >= 8 else {
            throw TraceParseError.invalidFile("The file is too short to be an xniff dump")
        }

        let first = try reader.readUInt32()
        if first == fileMagic {
            let version = try reader.readUInt16()
            guard version == fileVersion else {
                throw TraceParseError.unsupported("Unsupported xniff file version \(version)")
            }
            try reader.skip(2)
        } else {
            guard data.count >= 16 else {
                throw TraceParseError.invalidFile("The file is too short to contain an xniff record")
            }
            reader.offset = 0
        }

        var pending: [PendingEvent] = []
        var fallbackCalls: [FallbackCallKey: [UInt64]] = [:]
        var nextFallbackCallID: UInt64 = 1

        while reader.remaining >= 16 {
            let recordStart = reader.offset
            let recordLength = Int(try reader.readUInt32())
            _ = try reader.readUInt16() // entry type
            let version = try reader.readUInt16()
            let sequence = try reader.readUInt64()

            guard version == recordVersion else {
                throw TraceParseError.unsupported("Unsupported record version \(version) at byte \(recordStart)")
            }
            guard recordLength >= 40, recordLength <= maximumRecordLength,
                  recordStart + recordLength <= data.count else {
                throw TraceParseError.invalidFile("Invalid record length \(recordLength) at byte \(recordStart)")
            }

            let recordEnd = recordStart + recordLength
            let processID = try reader.readUInt32()
            let threadID = try reader.readUInt32()
            let timestamp = try reader.readUInt64()
            guard let direction = TraceDirection(rawValue: try reader.readUInt16()) else {
                throw TraceParseError.invalidFile("Invalid event direction at byte \(recordStart)")
            }
            guard let api = TraceAPI(rawValue: try reader.readUInt16()) else {
                throw TraceParseError.invalidFile("Invalid API at byte \(recordStart)")
            }
            var function = try reader.readUInt32()
            var returnValue: UInt64 = 0
            var arguments: [UInt64] = []
            var peerProcessID: UInt32?
            var serviceName: String?
            var callID: UInt64?
            var payloads: [TracePayloadSlice] = []
            var backtracePCs: [UInt64] = []
            var backtraceSymbols: [UInt64: BacktraceSymbol] = [:]
            var machMessageID: Int32?
            var diagnostic: String?

            while reader.offset + 8 <= recordEnd {
                let sectionType = try reader.readUInt16()
                _ = try reader.readUInt16() // flags
                let sectionLength = Int(try reader.readUInt32())
                let sectionStart = reader.offset
                let sectionEnd = sectionStart + sectionLength
                guard sectionLength >= 0, sectionEnd <= recordEnd else {
                    throw TraceParseError.invalidFile("Invalid section length at byte \(sectionStart)")
                }

                switch sectionType {
                case 1 where api == .machMessage || api == .machMessage2:
                    if sectionLength >= 128 {
                        var section = BinaryReader(data: data, offset: sectionStart, end: sectionEnd)
                        _ = try section.readUInt32()
                        _ = try section.readUInt32()
                        _ = try section.readUInt32()
                        _ = try section.readUInt32()
                        _ = try section.readUInt32()
                        _ = try section.readUInt32()
                        _ = try section.readUInt64()
                        _ = try section.readUInt64()
                        returnValue = try section.readUInt64()
                        try section.skip(16)
                        arguments = try (0..<8).map { _ in try section.readUInt64() }
                    }
                case 2 where api == .machMessage || api == .machMessage2:
                    if sectionLength >= 24 {
                        var section = BinaryReader(data: data, offset: sectionStart, end: sectionEnd)
                        try section.skip(20)
                        machMessageID = Int32(bitPattern: try section.readUInt32())
                    }
                    payloads.append(.init(
                        kind: .message,
                        format: 0,
                        originalLength: sectionLength,
                        isTruncated: false,
                        range: sectionStart..<sectionEnd
                    ))
                case 7 where api == .xpc:
                    if sectionLength >= 12 {
                        var section = BinaryReader(data: data, offset: sectionStart, end: sectionEnd)
                        let slot = try section.readUInt8()
                        let format = try section.readUInt8()
                        let serializedFlags = try section.readUInt16()
                        let originalLength = Int(try section.readUInt32())
                        let storedLength = min(Int(try section.readUInt32()), section.remaining)
                        let payloadStart = section.offset
                        payloads.append(.init(
                            kind: TracePayloadKind(rawValue: slot) ?? .unknown,
                            format: format,
                            originalLength: originalLength,
                            isTruncated: serializedFlags & 1 != 0,
                            range: payloadStart..<(payloadStart + storedLength)
                        ))
                    }
                case 9 where api == .diagnostic:
                    if sectionLength >= 8 {
                        var section = BinaryReader(data: data, offset: sectionStart, end: sectionEnd)
                        let messageLength = min(Int(try section.readUInt32()), section.remaining - 4)
                        try section.skip(4)
                        diagnostic = try section.readString(count: max(0, messageLength))
                    }
                case 10 where api == .xpc:
                    if sectionLength >= 104 {
                        var section = BinaryReader(data: data, offset: sectionStart, end: sectionEnd)
                        _ = try section.readUInt32()
                        _ = try section.readUInt32()
                        function = try section.readUInt32()
                        let peer = try section.readUInt32()
                        if peer != 0 { peerProcessID = peer }
                        returnValue = try section.readUInt64()
                        arguments = try (0..<8).map { _ in try section.readUInt64() }
                        let lengths = try (0..<4).map { _ in Int(try section.readUInt32()) }
                        var strings: [String] = []
                        for length in lengths where length > 0 {
                            guard length <= section.remaining else { break }
                            strings.append(try section.readString(count: length))
                        }
                        serviceName = strings.first(where: { !$0.isEmpty })
                    }
                case 13:
                    if sectionLength >= 8 {
                        var section = BinaryReader(data: data, offset: sectionStart, end: sectionEnd)
                        let wireID = try section.readUInt64()
                        if wireID != 0 { callID = wireID }
                    }
                case 11:
                    if sectionLength >= 8 {
                        var section = BinaryReader(data: data, offset: sectionStart, end: sectionEnd)
                        let count = min(Int(try section.readUInt32()), 32)
                        try section.skip(4)
                        backtracePCs = try (0..<count).map { _ in try section.readUInt64() }
                    }
                case 12:
                    backtraceSymbols = try parseBacktraceSymbols(
                        data: data,
                        start: sectionStart,
                        end: sectionEnd
                    )
                default:
                    break
                }
                reader.offset = sectionEnd
            }
            reader.offset = recordEnd

            if callID == nil {
                let key = FallbackCallKey(pid: processID, tid: threadID, api: api.rawValue, function: function)
                if direction == .entry {
                    callID = nextFallbackCallID
                    nextFallbackCallID += 1
                    fallbackCalls[key, default: []].append(callID!)
                } else if var stack = fallbackCalls[key], let matched = stack.popLast() {
                    callID = matched
                    fallbackCalls[key] = stack.isEmpty ? nil : stack
                } else {
                    callID = nextFallbackCallID
                    nextFallbackCallID += 1
                }
            }

            let functionName: String
            switch api {
            case .xpc: functionName = TraceModel.functionName(function)
            case .machMessage: functionName = "mach_msg"
            case .machMessage2: functionName = "mach_msg2"
            case .diagnostic: functionName = "diagnostic"
            }
            let role = TraceModel.role(function: function, direction: direction, api: api)
            let summary = diagnostic
                ?? serviceName
                ?? machMessageID.map { "message id \($0)" }
                ?? payloads.map(\.name).joined(separator: ", ")

            pending.append(.init(
                sequence: sequence,
                processID: processID,
                threadID: threadID,
                timestamp: timestamp,
                api: api,
                direction: direction,
                function: function,
                functionName: functionName,
                role: role,
                callID: callID,
                peerProcessID: peerProcessID,
                serviceName: serviceName,
                returnValue: returnValue,
                arguments: arguments,
                payloads: payloads,
                backtrace: backtracePCs.enumerated().map { index, pc in
                    let symbol = backtraceSymbols[pc]
                    return TraceFrame(
                        id: index,
                        programCounter: pc,
                        symbolAddress: symbol?.address,
                        symbolName: symbol?.name,
                        imagePath: symbol?.image
                    )
                },
                summary: summary
            ))
        }

        let baseline = pending.first?.timestamp ?? 0
        let events = pending.enumerated().map { index, item in
            TraceEvent(
                id: UInt64(index + 1),
                sequence: item.sequence,
                processID: item.processID,
                threadID: item.threadID,
                timestampNanoseconds: item.timestamp,
                relativeSeconds: Double(item.timestamp >= baseline ? item.timestamp - baseline : 0) / 1_000_000_000,
                api: item.api,
                direction: item.direction,
                function: item.function,
                functionName: item.functionName,
                role: item.role,
                callID: item.callID,
                peerProcessID: item.peerProcessID,
                serviceName: item.serviceName,
                returnValue: item.returnValue,
                arguments: item.arguments,
                payloads: item.payloads,
                backtrace: item.backtrace,
                summary: item.summary
            )
        }
        return TraceDocument(
            url: sourceURL,
            data: data,
            events: events,
            calls: makeCalls(events)
        )
    }

    private static func makeCalls(_ events: [TraceEvent]) -> [TraceCall] {
        var indexes: [TraceCallID: Int] = [:]
        var grouped: [(id: TraceCallID, events: [TraceEvent])] = []
        for event in events {
            let id = TraceCallID(processID: event.processID, callID: event.callID ?? event.id)
            if let index = indexes[id] {
                grouped[index].events.append(event)
            } else {
                indexes[id] = grouped.count
                grouped.append((id, [event]))
            }
        }
        return grouped.map { TraceCall(id: $0.id, events: $0.events) }
    }

    private static func parseBacktraceSymbols(
        data: Data,
        start: Int,
        end: Int
    ) throws -> [UInt64: BacktraceSymbol] {
        guard end - start >= 8 else { return [:] }
        var reader = BinaryReader(data: data, offset: start, end: end)
        let count = min(Int(try reader.readUInt32()), 32)
        _ = try reader.readUInt32()
        guard reader.remaining >= count * 24 else { return [:] }

        var entries: [(pc: UInt64, address: UInt64, nameLength: Int, imageLength: Int)] = []
        entries.reserveCapacity(count)
        for _ in 0..<count {
            entries.append((
                try reader.readUInt64(),
                try reader.readUInt64(),
                Int(try reader.readUInt32()),
                Int(try reader.readUInt32())
            ))
        }

        var result: [UInt64: BacktraceSymbol] = [:]
        for entry in entries {
            guard entry.nameLength <= reader.remaining else { break }
            let name = entry.nameLength == 0 ? nil : try reader.readString(count: entry.nameLength)
            guard entry.imageLength <= reader.remaining else { break }
            let image = entry.imageLength == 0 ? nil : try reader.readString(count: entry.imageLength)
            result[entry.pc] = BacktraceSymbol(
                address: entry.address == 0 ? nil : entry.address,
                name: name,
                image: image
            )
        }
        return result
    }
}

private struct BacktraceSymbol {
    let address: UInt64?
    let name: String?
    let image: String?
}

private struct FallbackCallKey: Hashable {
    let pid: UInt32
    let tid: UInt32
    let api: UInt16
    let function: UInt32
}

private struct PendingEvent {
    let sequence: UInt64
    let processID: UInt32
    let threadID: UInt32
    let timestamp: UInt64
    let api: TraceAPI
    let direction: TraceDirection
    let function: UInt32
    let functionName: String
    let role: TraceRole
    let callID: UInt64?
    let peerProcessID: UInt32?
    let serviceName: String?
    let returnValue: UInt64
    let arguments: [UInt64]
    let payloads: [TracePayloadSlice]
    let backtrace: [TraceFrame]
    let summary: String
}
