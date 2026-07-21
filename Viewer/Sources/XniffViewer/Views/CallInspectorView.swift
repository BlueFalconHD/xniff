import SwiftUI
import XniffViewerCore

struct CallInspectorView: View {
    let document: TraceDocument?
    let call: TraceCall?

    var body: some View {
        Group {
            if let document, let call {
                VStack(spacing: 0) {
                    callHeader(call)
                    Divider()
                    HSplitView {
                        MessagePaneView(
                            title: requestTitle(call),
                            side: .request,
                            document: document,
                            event: call.request,
                            counterpartEvent: nil
                        )
                        .frame(minWidth: 420)

                        MessagePaneView(
                            title: "Response",
                            side: .response,
                            document: document,
                            event: call.response,
                            counterpartEvent: call.request
                        )
                        .frame(minWidth: 420)
                    }
                }
            } else {
                ContentUnavailableView(
                    "No Call Selected",
                    systemImage: "rectangle.bottomhalf.inset.filled",
                    description: Text("Select a row to inspect both sides of the call.")
                )
            }
        }
    }

    private func callHeader(_ call: TraceCall) -> some View {
        HStack(spacing: 10) {
            Text(call.role.label.uppercased())
                .font(.caption.weight(.bold))
                .foregroundStyle(.secondary)
            Text(call.serviceName ?? call.functionName)
                .font(.headline)
                .lineLimit(1)
                .textSelection(.enabled)
            if call.serviceName != nil {
                Text(call.functionName)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
            }
            Spacer()
            Text("Call \(call.id.callID)")
                .foregroundStyle(.secondary)
                .monospacedDigit()
            if let duration = call.durationSeconds {
                Text(String(format: "%.3f ms", duration * 1_000))
                    .foregroundStyle(.secondary)
                    .monospacedDigit()
            }
        }
        .padding(.horizontal, 12)
        .frame(height: 40)
    }

    private func requestTitle(_ call: TraceCall) -> String {
        call.role == .incoming ? "Incoming Request" : "Request"
    }
}
