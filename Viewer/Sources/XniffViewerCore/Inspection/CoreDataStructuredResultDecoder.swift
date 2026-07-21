import Foundation

enum CoreDataStructuredResultDecoder {
    static func decode(
        _ data: Data,
        expectedCount: UInt32
    ) -> [TraceField]? {
        guard let bufferCountValue = data.coreDataUInt32(at: 52),
              let resultCount = data.coreDataUInt32(at: 36),
              let snapshotTime = data.coreDataUInt64(at: 40),
              let bufferCapacity = data.coreDataUInt32(at: 48),
              let flags = data.coreDataUInt32(at: 80) else {
            return nil
        }

        let bufferCount = Int(bufferCountValue)
        guard bufferCount > 0,
              bufferCount <= (data.count - 136) / 24 else {
            return nil
        }

        let pointerTableStart = 128
        // _rawRowDataForXPCRequest writes pointer placeholders, a marker,
        // buffer sizes, and absolute buffer offsets in that order.
        let tableMarkerOffset = pointerTableStart + 8 * bufferCount
        let sizesStart = tableMarkerOffset + 8
        let offsetsStart = sizesStart + 8 * bufferCount
        let tableEnd = offsetsStart + 8 * bufferCount
        guard tableEnd <= data.count,
              data.coreDataUInt64(at: tableMarkerOffset) == CoreDataResultBufferDecoder.marker else {
            return nil
        }

        var sizes: [Int] = []
        var offsets: [Int] = []
        for index in 0..<bufferCount {
            guard let size = data.coreDataInt(at: sizesStart + 8 * index),
                  let offset = data.coreDataInt(at: offsetsStart + 8 * index),
                  offset >= tableEnd,
                  size <= data.count - offset else {
                return nil
            }
            sizes.append(size)
            offsets.append(offset)
        }

        let buffers = offsets.indices.map { index in
            TraceValue.object(type: "Buffer \(index)", fields: [
                TraceField(name: "Offset", value: .unsigned(UInt64(offsets[index]))),
                TraceField(name: "Size", value: .unsigned(UInt64(sizes[index]))),
                TraceField(
                    name: "Bytes",
                    value: .data(
                        data.subdata(in: offsets[index]..<(offsets[index] + sizes[index])),
                        interpretation: nil
                    )
                ),
            ])
        }

        var fields = [
            TraceField(name: "Encoding", value: .string("Structured fetch rows")),
            TraceField(name: "Result count", value: .unsigned(UInt64(resultCount))),
            TraceField(name: "Buffer count", value: .unsigned(UInt64(bufferCountValue))),
            TraceField(name: "Buffer capacity", value: .unsigned(UInt64(bufferCapacity))),
            TraceField(name: "Snapshot time", value: .double(Double(snapshotTime))),
            TraceField(name: "Flags", value: .unsigned(UInt64(flags))),
            TraceField(name: "Buffers", value: .array(buffers)),
        ]
        if let rows = decodeRowHeaders(
            data,
            offsets: offsets,
            sizes: sizes,
            expectedCount: Int(expectedCount)
        ) {
            fields.append(TraceField(name: "Rows", value: .array(rows)))
        } else {
            fields.append(TraceField(
                name: "Row decoding",
                value: .string("The buffer table is valid, but the linked row headers are inconsistent")
            ))
        }
        return fields
    }

    private static func decodeRowHeaders(
        _ data: Data,
        offsets: [Int],
        sizes: [Int],
        expectedCount: Int
    ) -> [TraceValue]? {
        guard let firstOffset = offsets.first else { return nil }

        let bufferRanges = offsets.indices.map {
            offsets[$0]..<(offsets[$0] + sizes[$0])
        }
        var position = firstOffset
        var visited: Set<Int> = []
        var rows: [TraceValue] = []

        while rows.count < expectedCount {
            guard visited.insert(position).inserted,
                  let currentBuffer = bufferRanges.firstIndex(where: { $0.contains(position) }),
                  bufferRanges[currentBuffer].upperBound - position >= 32,
                  let markerValue = data.coreDataUInt32(at: position),
                  let nextBufferValue = data.coreDataUInt32(at: position + 4),
                  let entityID = data.coreDataUInt32(at: position + 8),
                  let metadata = data.coreDataUInt32(at: position + 12),
                  let nextOffsetValue = data.coreDataUInt64(at: position + 16),
                  let primaryKey = data.coreDataUInt64(at: position + 24) else {
                return nil
            }

            if Int32(bitPattern: markerValue) < 0 {
                // Negative row indices are cross-buffer forwarding records.
                guard let target = absoluteRowOffset(
                    buffer: nextBufferValue,
                    offset: nextOffsetValue,
                    bufferOffsets: offsets
                ) else { return nil }
                position = target
                continue
            }

            let nextPosition = absoluteRowOffset(
                buffer: nextBufferValue,
                offset: nextOffsetValue,
                bufferOffsets: offsets
            )
            var propertyEnd = bufferRanges[currentBuffer].upperBound
            if let nextPosition, bufferRanges[currentBuffer].contains(nextPosition) {
                propertyEnd = nextPosition
            }
            guard position + 32 <= propertyEnd else { return nil }

            rows.append(.object(type: "Row \(rows.count)", fields: [
                TraceField(name: "Row index", value: .unsigned(UInt64(markerValue))),
                TraceField(name: "SQL entity ID", value: .unsigned(UInt64(entityID))),
                TraceField(name: "Record metadata", value: .unsigned(UInt64(metadata))),
                TraceField(name: "Primary key", value: .unsigned(primaryKey)),
                TraceField(
                    name: "Next row offset",
                    value: .string(nextPosition.map(String.init) ?? "End")
                ),
                TraceField(
                    name: "Encoded property storage",
                    value: .data(data.subdata(in: (position + 32)..<propertyEnd), interpretation: nil)
                ),
            ]))

            guard let nextPosition else { break }
            position = nextPosition
        }

        return rows.count == expectedCount ? rows : nil
    }

    private static func absoluteRowOffset(
        buffer: UInt32,
        offset: UInt64,
        bufferOffsets: [Int]
    ) -> Int? {
        guard buffer & 0x8000_0000 == 0,
              Int(buffer) < bufferOffsets.count,
              offset <= UInt64(Int.max),
              Int(offset) <= Int.max - bufferOffsets[Int(buffer)] else {
            return nil
        }
        return bufferOffsets[Int(buffer)] + Int(offset)
    }
}
