// swift-tools-version:5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "swiftBee",
    dependencies: [
        // Dependencies declare other packages that this package depends on.
        // .package(url: /* package url */, from: "1.0.0"),
        .package(
            url: "https://github.com/johnsundell/files.git",
            from: "4.2.0"
        )
    ],
    targets: [
        .executableTarget(
            name: "swiftBee",
            dependencies: ["swiftBeeCore"]),
        .target(
            name: "swiftBeeCore",
            dependencies: [.product(name: "Files", package: "files")]),
        .testTarget(
            name: "swiftBeeTests",
            dependencies: ["swiftBee"]),
    ]
)
