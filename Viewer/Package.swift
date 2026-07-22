// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "XniffViewer",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "XniffViewerCore", targets: ["XniffViewerCore"]),
        .executable(name: "xniff-viewer", targets: ["XniffViewer"]),
        .executable(name: "xniff-print", targets: ["XniffPrint"]),
    ],
    targets: [
        .target(name: "XniffViewerCore"),
        .executableTarget(
            name: "XniffViewer",
            dependencies: ["XniffViewerCore"]
        ),
        .executableTarget(
            name: "XniffPrint",
            dependencies: ["XniffViewerCore"]
        ),
        .testTarget(
            name: "XniffViewerCoreTests",
            dependencies: ["XniffViewerCore"]
        ),
        .testTarget(
            name: "XniffViewerTests",
            dependencies: ["XniffViewer"]
        ),
        .testTarget(
            name: "XniffPrintTests",
            dependencies: ["XniffPrint"]
        ),
    ]
)
