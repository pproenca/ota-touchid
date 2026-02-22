// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "OTATouchID",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "ota-touchid", targets: ["CLI"]),
    ],
    targets: [
        .target(
            name: "Shared",
            linkerSettings: [
                .linkedFramework("Security"),
            ]
        ),
        .target(
            name: "ServerLib",
            dependencies: ["Shared"],
            linkerSettings: [
                .linkedFramework("LocalAuthentication"),
                .linkedFramework("Security"),
            ]
        ),
        .target(
            name: "ClientLib",
            dependencies: ["Shared"]
        ),
        .executableTarget(
            name: "CLI",
            dependencies: ["ServerLib", "ClientLib", "Shared"],
            linkerSettings: [
                .linkedFramework("LocalAuthentication"),
                .linkedFramework("Security"),
            ]
        ),
        .testTarget(
            name: "SharedTests",
            dependencies: ["Shared"]
        ),
        .testTarget(
            name: "ClientLibTests",
            dependencies: ["ClientLib", "Shared"]
        ),
        .testTarget(
            name: "CLIIntegrationTests",
            dependencies: ["CLI"]
        ),
    ]
)
