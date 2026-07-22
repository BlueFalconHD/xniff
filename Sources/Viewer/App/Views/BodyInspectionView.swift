import SwiftUI
import XniffViewerCore

struct BodyInspectionView: View {
    let payloadID: UUID
    let inspection: BodyInspection
    let parent: BodyInspection?
    let data: Data
    let highlightedRange: Range<Int>?
    let detailsHeight: CGFloat?
    let detailsNaturalHeightChanged: (CGFloat) -> Void
    let detailsResized: (CGFloat) -> Void
    let viewInParent: (String, Range<Int>) -> Void

    var body: some View {
        GeometryReader { proxy in
            VStack(spacing: 0) {
                BodyInspectionDetailsSection(
                    details: inspection.details,
                    alignedHeight: detailsHeight,
                    maximumHeight: max(0, proxy.size.height - 80),
                    naturalHeightChanged: detailsNaturalHeightChanged,
                    resized: detailsResized
                )
                content
                    .frame(minHeight: 0)
                    .layoutPriority(1)
            }
        }
    }

    @ViewBuilder
    private var content: some View {
        switch inspection.content {
        case .bytes(let bytes):
            HexView(
                payloadID: payloadID,
                data: bytes,
                highlightedRange: highlightedRange
            )
        case .tree(let value):
            BodyTreeView(
                payloadID: "\(payloadID.uuidString):\(inspection.id)",
                value: value,
                data: data,
                highlightedRange: highlightedRange,
                parentInspectorName: parent?.name
            ) { range in
                guard let parent else { return }
                viewInParent(parent.id, range)
            }
        }
    }
}
