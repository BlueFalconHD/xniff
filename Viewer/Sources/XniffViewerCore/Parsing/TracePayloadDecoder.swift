import Foundation

public struct TracePayloadInput: Sendable {
    public let slice: TracePayloadSlice
    public let data: Data

    public init(slice: TracePayloadSlice, data: Data) {
        self.slice = slice
        self.data = data
    }
}

public struct DecodedTracePayload: Sendable, Identifiable {
    public let id: UUID
    public let slice: TracePayloadSlice
    public let data: Data
    public let value: TraceValue
    public let inspections: [BodyInspection]

    public init(
        slice: TracePayloadSlice,
        data: Data,
        value: TraceValue,
        counterpartBody: TraceValue? = nil
    ) {
        self.id = slice.id
        self.slice = slice
        self.data = data
        self.value = value
        self.inspections = BodyInspectorRegistry.standard.inspections(
            for: value,
            data: data,
            counterpartBody: counterpartBody
        )
    }

    public func inspection(withID id: String) -> BodyInspection? {
        inspections.first { $0.id == id }
    }

    public func parent(of inspection: BodyInspection) -> BodyInspection? {
        inspection.parentID.flatMap(inspection(withID:))
    }
}

public enum TracePayloadDecoder {
    @concurrent
    public static func decode(
        _ inputs: [TracePayloadInput],
        counterpartBody: TraceValue? = nil
    ) async -> [DecodedTracePayload] {
        inputs.map { input in
            DecodedTracePayload(
                slice: input.slice,
                data: input.data,
                value: EmbeddedPayloadDecoder.decode(input.data, format: input.slice.format),
                counterpartBody: counterpartBody
            )
        }
    }
}
