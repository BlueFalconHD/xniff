import SwiftUI
import XniffViewerCore

struct BodyInspectionDetailsSection: View {
    let details: [BodyInspectionDetail]
    let alignedHeight: CGFloat?
    let maximumHeight: CGFloat
    let naturalHeightChanged: (CGFloat) -> Void
    let resized: (CGFloat) -> Void

    @State private var measuredHeight: CGFloat = 0
    @State private var resizeStartHeight: CGFloat?

    private var displayedHeight: CGFloat? {
        alignedHeight.map { min(max(0, $0), maximumHeight) }
    }

    private var isVisible: Bool {
        !details.isEmpty || (displayedHeight ?? 0) > 0
    }

    var body: some View {
        if isVisible {
            VStack(spacing: 0) {
                detailsContent
                    .frame(height: displayedHeight, alignment: .topLeading)
                    .clipped()
                    .background {
                        naturalHeightReader
                    }

                resizeHandle
            }
            .onPreferenceChange(BodyDetailsNaturalHeightKey.self) { height in
                measuredHeight = height
                naturalHeightChanged(height)
            }
        } else {
            Color.clear
                .frame(height: 0)
                .onAppear { naturalHeightChanged(0) }
                .onChange(of: details) { naturalHeightChanged(0) }
        }
    }

    @ViewBuilder
    private var detailsContent: some View {
        if details.isEmpty {
            Color.clear
        } else {
            BodyInspectionDetailsView(details: details)
        }
    }

    @ViewBuilder
    private var naturalHeightReader: some View {
        if details.isEmpty {
            Color.clear
                .preference(key: BodyDetailsNaturalHeightKey.self, value: 0)
        } else {
            BodyInspectionDetailsView(details: details)
                .fixedSize(horizontal: false, vertical: true)
                .hidden()
                .accessibilityHidden(true)
                .background {
                    GeometryReader { proxy in
                        Color.clear.preference(
                            key: BodyDetailsNaturalHeightKey.self,
                            value: proxy.size.height
                        )
                    }
                }
        }
    }

    private var resizeHandle: some View {
        Rectangle()
            .fill(.separator)
            .frame(height: 1)
            .frame(height: 7)
            .contentShape(Rectangle())
            .help("Drag to resize request and response metadata")
            .gesture(
                DragGesture(minimumDistance: 0, coordinateSpace: .global)
                    .onChanged { value in
                        if resizeStartHeight == nil {
                            resizeStartHeight = displayedHeight ?? measuredHeight
                        }
                        let startHeight = resizeStartHeight ?? 0
                        resized(min(maximumHeight, max(0, startHeight + value.translation.height)))
                    }
                    .onEnded { _ in
                        resizeStartHeight = nil
                    }
            )
    }
}

struct BodyInspectionDetailsView: View {
    let details: [BodyInspectionDetail]

    var body: some View {
        Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 5) {
            ForEach(details) { detail in
                GridRow(alignment: .firstTextBaseline) {
                    Text(detail.label)
                        .foregroundStyle(.secondary)
                        .gridColumnAlignment(.trailing)
                    Text(detail.value)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .help(detail.value)
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

private struct BodyDetailsNaturalHeightKey: PreferenceKey {
    static let defaultValue: CGFloat = 0

    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) {
        value = max(value, nextValue())
    }
}
