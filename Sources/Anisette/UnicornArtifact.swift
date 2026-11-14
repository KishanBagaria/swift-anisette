import Foundation

struct UnicornArtifact {
    let url: URL
    let archiveHash: String
    let libraryHash: String
    let name: String
    var member: String { "unicorn/lib/\(name)" }
    var relativePath: String { "unicorn/2.1.4/\(libraryHash)/\(name)" }

    private static func artifactURL(_ path: String, _ name: String) -> URL {
        URL(string: "https://files.pythonhosted.org/packages/" + path + "/" + name)!
    }

    static let current: Self = {
        #if os(macOS) && arch(arm64)
        return macOSArm
        #elseif os(macOS)
        return macOSIntel
        #elseif arch(arm64)
        return linuxArm
        #else
        return linuxIntel
        #endif
    }()

    static let all = [macOSArm, macOSIntel, linuxArm, linuxIntel]

    static let macOSArm = Self(
        url: artifactURL("6c/ae/4943c6f8524d729ec7d5e69df6407ea05d710fe77471d91cecf3fc64eb57",
                         "unicorn-2.1.4-cp37-abi3-macosx_11_0_arm64.whl"),
        archiveHash: "d6c93e0f60328d8f4a1792af3f834137a28050fcc2305f2ec01efe8558a9844e",
        libraryHash: "7207c8e3d7a63118fb0bca73e01816797fd51b1d8a39a4cbc7abfd562ee59c85", name: "libunicorn.2.dylib"
    )

    static let macOSIntel = Self(
        url: artifactURL("c8/a7/92b47771e2107a201632a199cec91e8a81ee8a071ca6b7e7d600d8c61ac9",
                         "unicorn-2.1.4-cp37-abi3-macosx_10_9_x86_64.whl"),
        archiveHash: "2a6f738fab5fabffa56af1e7bbf16ea1e91466c342f8dc64f125bd70f36c6b80",
        libraryHash: "51c4a6f3ce22628ecd3acd1c49b921a818ffb989ca2c473134cc7eb06094f256", name: "libunicorn.2.dylib"
    )

    static let linuxArm = Self(
        url: artifactURL("33/9f/32d41eb942221bcf4417cdc65537fc8b3bbbd6079d6c161e621f1dd4e94a",
                         "unicorn-2.1.4-cp37-abi3-manylinux_2_17_aarch64.manylinux2014_aarch64.whl"),
        archiveHash: "bd1fb0c9af5f57e356d8a96928b4fe045b2e18f308ef23b481d5f970008aa722",
        libraryHash: "a0b99458a82e268aee258205a40590411c3a9f28e42abf2942ce4e87b7d9ac65", name: "libunicorn.so.2"
    )

    static let linuxIntel = Self(
        url: artifactURL("e7/df/ded5e3684c2d7600b30cc8a7530277b8cb36644a1a9d34cade7ebb45604c",
                         "unicorn-2.1.4-cp37-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl"),
        archiveHash: "9d6e6dea140560de4ebd8446661f7ef84a357d428c14a3ef09dacd306ec8c239",
        libraryHash: "ddb196ec82b52e502c18e4a34478bf7b9f61c83c2ebaa95c74d8ded45a95da9c", name: "libunicorn.so.2"
    )

    func resolve(in cacheDirectory: URL, http: AnisetteHTTPClient) async throws -> URL {
        let destination = cacheDirectory.appendingPathComponent(relativePath)
        if let data = try? Data(contentsOf: destination, options: .mappedIfSafe),
           Resources.verify(data, hash: libraryHash) { return destination }
        try await UnicornInstaller.shared.install(self, to: destination, http: http)
        return destination
    }

    static func member(_ name: String, in zip: Data) throws -> Data {
        try require(zip.count >= 22 && zip.count <= 64 << 20, "Invalid Unicorn archive size")
        return try RestoreArchive.contents(of: name, in: zip, limit: 64 << 20)
    }
}

private actor UnicornInstaller {
    static let shared = UnicornInstaller()

    func install(_ artifact: UnicornArtifact, to destination: URL, http: AnisetteHTTPClient) async throws {
        let data = try await http.fetch(artifact.url, nil)
        try require(Resources.verify(data, hash: artifact.archiveHash), "Unicorn archive failed integrity verification")
        let library = try UnicornArtifact.member(artifact.member, in: data)
        try require(Resources.verify(library, hash: artifact.libraryHash), "Unicorn library failed integrity verification")
        try Resources.writePrivate(library, to: destination)
    }
}
