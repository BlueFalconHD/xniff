import Foundation

enum XPCAttribution {
    private struct ObjectKey: Hashable {
        let processID: UInt32
        let kind: XPCObjectKind
        let object: UInt64
    }

    private struct Lifetime {
        var pendingEventIndexes: [Int] = []
        var serviceName: String?
    }

    static func applyExactServiceNames(to events: [TraceEvent]) -> [TraceEvent] {
        var result = events
        var lifetimes: [ObjectKey: Lifetime] = [:]

        func finish(_ key: ObjectKey) {
            guard let lifetime = lifetimes.removeValue(forKey: key),
                  let serviceName = lifetime.serviceName else { return }
            for index in lifetime.pendingEventIndexes where result[index].serviceName == nil {
                result[index] = result[index].replacingExactServiceName(serviceName)
            }
        }

        for index in result.indices {
            let event = result[index]
            guard let object = event.xpcObjectID,
                  let kind = event.xpcObjectKind else { continue }
            let key = ObjectKey(processID: event.processID, kind: kind, object: object)

            if event.xpcObjectLifecycle == .created {
                finish(key)
            }

            var lifetime = lifetimes[key] ?? Lifetime()
            if let eventService = event.serviceName,
               let existingService = lifetime.serviceName,
               eventService != existingService {
                // A changed immutable name means the address was reused without
                // a captured cancellation. End the old lifetime conservatively.
                lifetimes[key] = lifetime
                finish(key)
                lifetime = Lifetime()
            }
            if let serviceName = lifetime.serviceName ?? event.serviceName {
                lifetime.serviceName = serviceName
                for pendingIndex in lifetime.pendingEventIndexes
                    where result[pendingIndex].serviceName == nil {
                    result[pendingIndex] = result[pendingIndex]
                        .replacingExactServiceName(serviceName)
                }
                lifetime.pendingEventIndexes.removeAll(keepingCapacity: false)
                if result[index].serviceName == nil {
                    result[index] = result[index].replacingExactServiceName(serviceName)
                }
            } else {
                lifetime.pendingEventIndexes.append(index)
            }
            lifetimes[key] = lifetime

            if event.xpcObjectLifecycle == .cancelled {
                finish(key)
            }
        }

        for key in Array(lifetimes.keys) {
            finish(key)
        }
        return result
    }
}

private extension TraceEvent {
    func replacingExactServiceName(_ serviceName: String) -> TraceEvent {
        TraceEvent(
            id: id,
            sequence: sequence,
            processID: processID,
            threadID: threadID,
            timestampNanoseconds: timestampNanoseconds,
            relativeSeconds: relativeSeconds,
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
            backtrace: backtrace,
            summary: summary,
            peerAuditToken: peerAuditToken,
            xpcObjectID: xpcObjectID,
            xpcObjectKind: xpcObjectKind,
            xpcObjectLifecycle: xpcObjectLifecycle
        )
    }
}
