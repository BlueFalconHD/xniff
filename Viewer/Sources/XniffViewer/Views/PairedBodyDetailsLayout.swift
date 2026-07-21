import SwiftUI

struct PairedBodyDetailsLayout {
    private var naturalHeights: [MessageSide: CGFloat] = [:]
    private var resizedHeight: CGFloat?

    var alignedHeight: CGFloat? {
        resizedHeight ?? naturalHeights.values.max()
    }

    mutating func reportNaturalHeight(_ height: CGFloat, for side: MessageSide) {
        let normalizedHeight = max(0, ceil(height))
        guard abs((naturalHeights[side] ?? -1) - normalizedHeight) > 0.5 else { return }
        naturalHeights[side] = normalizedHeight
    }

    mutating func resize(to height: CGFloat) {
        resizedHeight = max(0, height)
    }

    mutating func reset() {
        naturalHeights.removeAll()
        resizedHeight = nil
    }
}
