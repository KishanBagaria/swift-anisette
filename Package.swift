// swift-tools-version:6.2

import PackageDescription

let package = Package(
    name: "swift-anisette",
    platforms: [.macOS(.v14)],
    products: [.library(name: "Anisette", targets: ["Anisette"])],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto", from: "5.0.0"),
        .package(url: "https://github.com/apple/swift-asn1", from: "1.7.3"),
        .package(url: "https://github.com/KishanBagaria/lzfse-swift", revision: "bfdc057250a065ac1cb76dabc7b2484ba800b7c6"),
        .package(url: "https://github.com/KishanBagaria/libzbitmap", revision: "8408434bf13d4601f5de808b64037629b22d4a3e"),
        .package(url: "https://github.com/p-x9/MachOKit", revision: "86e3a0734c9f7fbb959ccbd4be233b378ed59815"),
    ],
    targets: [
        .target(
            name: "CAnisette",
            dependencies: [.product(name: "LZFSE", package: "lzfse-swift")],
            linkerSettings: [.linkedLibrary("z"), .linkedLibrary("dl", .when(platforms: [.linux]))]
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
            resources: [.process("Resources")]
        ),
        .testTarget(
            name: "AnisetteTests",
            dependencies: ["Anisette"]
        ),
    ]
)
