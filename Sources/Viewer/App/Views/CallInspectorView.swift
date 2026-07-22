import SwiftUI
import XniffViewerCore

struct CallInspectorView: View {
    let document: TraceDocument?
    let call: TraceCall?

    @State private var bodyDetailsLayout = PairedBodyDetailsLayout()

    var body: some View {
        Group {
            if let document, let call {
                HSplitView {
                    MessagePaneView(
                        title: requestTitle(call),
                        side: .request,
                        document: document,
                        event: call.request,
                        counterpartEvent: nil,
                        detailsHeight: bodyDetailsLayout.alignedHeight,
                        detailsNaturalHeightChanged: { height in
                            bodyDetailsLayout.reportNaturalHeight(height, for: .request)
                        },
                        detailsResized: { height in
                            bodyDetailsLayout.resize(to: height)
                        }
                    )
                    .frame(minWidth: 420)

                    MessagePaneView(
                        title: "Response",
                        side: .response,
                        document: document,
                        event: call.response,
                        counterpartEvent: call.request,
                        detailsHeight: bodyDetailsLayout.alignedHeight,
                        detailsNaturalHeightChanged: { height in
                            bodyDetailsLayout.reportNaturalHeight(height, for: .response)
                        },
                        detailsResized: { height in
                            bodyDetailsLayout.resize(to: height)
                        }
                    )
                    .frame(minWidth: 420)
                }
                .onChange(of: call.id) {
                    bodyDetailsLayout.reset()
                }
            } else {
                InspectorPlaceholderView(
                    title: "No Call Selected",
                    systemImage: "rectangle.bottomhalf.inset.filled",
                    description: "Select a row to inspect both sides of the call."
                )
            }
        }
    }

    private func requestTitle(_ call: TraceCall) -> String {
        call.role == .incoming ? "Incoming Request" : "Request"
    }
}
