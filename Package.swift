// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "spacesaving",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "spacesaving", targets: ["spacesaving"]),
    ],
    targets: [
        .target(
            name: "SpacesavingCore",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .executableTarget(
            name: "spacesaving",
            dependencies: ["SpacesavingCore"],
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .testTarget(
            name: "spacesavingTests",
            dependencies: ["SpacesavingCore"],
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ]
)
