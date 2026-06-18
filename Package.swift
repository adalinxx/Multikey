// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "Multikey",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "Multikey", targets: ["Multikey"]),
    ],
    targets: [
        .target(name: "Multikey"),
        .testTarget(name: "MultikeyTests", dependencies: ["Multikey"]),
    ]
)
