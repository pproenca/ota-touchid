// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "OTATouchID",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "ota-server", targets: ["Server"]),
        .executable(name: "ota-client", targets: ["Client"]),
    ],
    targets: [
        .target(
            name: "Shared",
            linkerSettings: [
                .linkedFramework("Security"),
            ]
        ),
        .executableTarget(
            name: "Server",
            dependencies: ["Shared"],
            linkerSettings: [
                .linkedFramework("LocalAuthentication"),
                .linkedFramework("Security"),
            ]
        ),
        .executableTarget(
            name: "Client",
            dependencies: ["Shared"]
        ),
        .testTarget(
            name: "SharedTests",
            dependencies: ["Shared"]
        ),
    ]
)
