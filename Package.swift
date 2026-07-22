// swift-tools-version: 6.2

import PackageDescription

let package = Package(
    name: "xniff",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "XniffViewerCore", targets: ["XniffViewerCore"]),
        .executable(name: "xniff-viewer", targets: ["XniffViewer"]),
        .executable(name: "xniff-print", targets: ["XniffPrint"]),
    ],
    targets: [
        .target(
            name: "XniffViewerCore",
            path: "Sources/Viewer/Core"
        ),
        .executableTarget(
            name: "XniffViewer",
            dependencies: ["XniffViewerCore"],
            path: "Sources/Viewer/App"
        ),
        .executableTarget(
            name: "XniffPrint",
            dependencies: ["XniffViewerCore"],
            path: "Sources/Viewer/PrintCLI"
        ),
        .testTarget(
            name: "XniffViewerCoreTests",
            dependencies: ["XniffViewerCore"],
            path: "Tests/Viewer/Core"
        ),
        .testTarget(
            name: "XniffViewerTests",
            dependencies: ["XniffViewer"],
            path: "Tests/Viewer/App"
        ),
        .testTarget(
            name: "XniffPrintTests",
            dependencies: ["XniffPrint"],
            path: "Tests/Viewer/PrintCLI"
        ),
    ]
)
