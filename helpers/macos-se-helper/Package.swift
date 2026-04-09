// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "ugrant-se-helper",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "ugrant-se-helper", targets: ["ugrant-se-helper"]),
    ],
    targets: [
        .executableTarget(
            name: "ugrant-se-helper",
            path: "Sources/ugrant-se-helper"
        ),
    ]
)
