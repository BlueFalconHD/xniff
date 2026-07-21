import SwiftUI

struct InspectorPlaceholderView: View {
    let title: String
    let systemImage: String
    let description: String

    var body: some View {
        GeometryReader { proxy in
            ZStack {
                Color.clear

                if proxy.size.height >= 96 {
                    VStack(spacing: 7) {
                        Image(systemName: systemImage)
                            .font(.title2)
                        Text(title)
                            .font(.headline)
                        Text(description)
                            .font(.caption)
                            .multilineTextAlignment(.center)
                    }
                    .foregroundStyle(.secondary)
                    .padding(12)
                } else {
                    Label(title, systemImage: systemImage)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .padding(.horizontal, 10)
                }
            }
            .frame(width: proxy.size.width, height: proxy.size.height)
            .clipped()
        }
        .frame(minWidth: 0, minHeight: 0)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(title)
        .accessibilityHint(description)
    }
}
