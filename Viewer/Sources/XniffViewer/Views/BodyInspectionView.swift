import SwiftUI
import XniffViewerCore

struct BodyInspectionView: View {
    let payloadID: UUID
    let inspection: BodyInspection
    let parent: BodyInspection?
    let data: Data
    let highlightedRange: Range<Int>?
    let viewInParent: (String, Range<Int>) -> Void

    var body: some View {
        VStack(spacing: 0) {
            if !inspection.details.isEmpty {
                BodyInspectionDetailsView(details: inspection.details)
                Divider()
            }
            content
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

private struct BodyInspectionDetailsView: View {
    let details: [BodyInspectionDetail]

    var body: some View {
        Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 5) {
            ForEach(details) { detail in
                GridRow(alignment: .firstTextBaseline) {
                    Text(detail.label)
                        .foregroundStyle(.secondary)
                        .gridColumnAlignment(.trailing)
                    Text(detail.value)
                        .textSelection(.enabled)
                        .gridColumnAlignment(.leading)
                }
            }
        }
        .font(.callout)
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
