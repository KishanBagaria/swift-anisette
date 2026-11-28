// swift-tools-version:6.2

import PackageDescription

let package = Package(
    name: "swift-anisette",
    platforms: [.macOS(.v14)],
    products: [.library(name: "Anisette", targets: ["Anisette"])],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto", from: "5.0.0"),
        .package(url: "https://github.com/apple/swift-asn1", from: "1.7.3"),
        .package(url: "https://github.com/KishanBagaria/lzfse-swift", .upToNextMinor(from: "1.0.2")),
        .package(url: "https://github.com/eafer/libzbitmap", .upToNextMinor(from: "0.1.0")),
        .package(url: "https://github.com/p-x9/MachOKit", revision: "e9896200470897df1c34b2bfc9f181fa8421bed9"),
    ],
    targets: [
        .target(
            name: "CAnisette",
            dependencies: [.product(name: "LZFSE", package: "lzfse-swift")],
            linkerSettings: [
                .linkedLibrary("z"),
                .linkedLibrary("dl", .when(platforms: [.linux])),
                .linkedLibrary("rt", .when(platforms: [.linux])),
            ]
        ),
        .target(
            name: "Anisette",
            dependencies: [
                "CAnisette",
                .product(name: "SwiftASN1", package: "swift-asn1"),
                .product(name: "libzbitmap", package: "libzbitmap"),
                .product(name: "MachOKit", package: "MachOKit"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "CryptoExtras", package: "swift-crypto"),
            ],
            resources: [.process("Resources")],
            linkerSettings: [.linkedFramework("Hypervisor", .when(platforms: [.macOS]))]
        ),
        .executableTarget(
            name: "anisette-example",
            dependencies: ["Anisette", .product(name: "Crypto", package: "swift-crypto")],
            path: "Examples/anisette-example"
        ),
        .testTarget(
            name: "AnisetteTests",
            dependencies: ["Anisette"]
        ),
    ]
)
