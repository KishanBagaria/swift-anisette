import Foundation
import SwiftASN1

actor AssetInstaller {
    static let shared = AssetInstaller()

    static let frameworkPaths = [
        "/System/Library/PrivateFrameworks/CoreADI.framework/Versions/A/adid",
        "/System/Library/PrivateFrameworks/CommerceKit.framework/Versions/A/Resources/commerce",
        "/System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/CoreFP",
        "/System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/Resources/CoreFP.icxs",
        "/System/Library/PrivateFrameworks/CoreFP.framework/Versions/A/fairplayd",
    ]

    func install(in directory: URL, http: AnisetteHTTPClient) async throws {
        let build = try PinnedBuild.current()
        let missing = Dictionary(uniqueKeysWithValues: build.assets.filter { file in
            guard let data = try? Data(contentsOf: directory.appendingPathComponent(file.name)) else { return true }
            return !Resources.verify(data, size: file.size, hash: file.hash)
        }.map { ($0.name, $0) })
        if missing.isEmpty { return }
        let archive = try await RestoreArchive.open(RemoteAssetFile(http: http, build: build).file)
        let frameworks = Self.frameworkPaths.filter { missing[Self.name($0)] != nil }
        let needsAMS = missing["AppleMediaServices"] != nil
        let needsKernel = missing["FairPlayIOKit"] != nil
        try await withThrowingTaskGroup(of: Void.self) { group in
            if !frameworks.isEmpty {
                group.addTask {
                    let tree = try await archive.volume(build.system, http: http)
                    for path in frameworks {
                        let data = try await Self.framework(path, in: tree)
                        try Self.verifyAndWrite(data, name: Self.name(path), missing: missing, build: build, directory: directory)
                    }
                }
            }
            if needsAMS {
                group.addTask {
                    let tree = try await archive.volume(build.sharedCache, http: http)
                    let data = try await DyldAsset().extract(from: tree)
                    try Self.verifyAndWrite(data, name: "AppleMediaServices", missing: missing, build: build, directory: directory)
                }
            }
            if needsKernel {
                group.addTask {
                    let data = try MachOExtraction.kernel(await archive.kernelCollection(build.kernelCache))
                    try Self.verifyAndWrite(data, name: "FairPlayIOKit", missing: missing, build: build, directory: directory)
                }
            }
            try await group.waitForAll()
        }
    }

    private static func verifyAndWrite(
        _ data: Data,
        name: String,
        missing: [String: PinnedBuild.Asset],
        build: PinnedBuild,
        directory: URL
    ) throws {
        guard let file = missing[name] else { throw AnisetteError("Unknown Apple asset") }
        try require(Resources.verify(data, size: file.size, hash: file.hash),
                    "Apple asset \(name) extracted from \(build.restoreImageURL.lastPathComponent) does not match the pinned "
                        + "build. Retry once; if it fails again, update swift-anisette")
        try Resources.writePrivate(data, to: directory.appendingPathComponent(name))
    }

    static func name(_ path: String) -> String { URL(fileURLWithPath: path).lastPathComponent }

    static func framework(_ path: String, in tree: APFSTree) async throws -> Data {
        var file = try await APFSFile.open(path, in: tree)
        if !path.hasSuffix(".icxs") { file = try await APFSFile.arm64e(file) }
        try require(file.size <= 64 << 20, "Apple framework exceeds size limit")
        return try await file.read(0, Int(file.size))
    }
}

extension RestoreArchive {
    func member(_ member: PinnedBuild.Member) async throws -> AssetFile {
        try await self.member(member.name, compressed: member.compressed, size: member.size)
    }

    func volume(_ member: PinnedBuild.Member, http: AnisetteHTTPClient) async throws -> (volume: PinnedBuild.Volume, tree: APFSTree) {
        let image = try await AEAFile.open(self.member(member), http: http)
        return (.init(member: member, filesystemSize: image.size), try await APFSTree.open(image.file))
    }

    func volume(_ volume: PinnedBuild.Volume, http: AnisetteHTTPClient) async throws -> APFSTree {
        let opened = try await self.volume(volume.member, http: http)
        try require(opened.volume.filesystemSize == volume.filesystemSize, "Unexpected filesystem size in \(volume.member.name)")
        return opened.tree
    }

    func kernelCollection(_ member: PinnedBuild.Member) async throws -> Data {
        let file = try await self.member(member)
        return try KernelAsset.collection(await file.read(0, Int(file.size)))
    }
}

enum KernelAsset {
    static func collection(_ data: Data) throws -> Data {
        let (payload, size) = try envelope(data)
        guard let size else { throw AnisetteError("Kernel payload does not declare an LZFSE size") }
        return try payload.lzfseDecoded(size: size)
    }

    /// SwiftASN1 validates the DER envelope; executable bytes remain an opaque
    /// OCTET STRING until the LZFSE and Mach-O readers validate them.
    static func envelope(_ data: Data) throws -> (payload: Data, decodedSize: Int?) {
        let root = try DER.parse(Array(data))
        guard root.identifier == .sequence, case .constructed(let children) = root.content else {
            throw AnisetteError("Invalid IM4P container")
        }
        var fields = children.makeIterator()
        let magic = try ASN1IA5String(derEncoded: &fields)
        let type = try ASN1IA5String(derEncoded: &fields)
        _ = try ASN1IA5String(derEncoded: &fields) // Description.
        let payload = try ASN1OctetString(derEncoded: &fields)
        try require(String(magic) == "IM4P" && String(type) == "krnl", "Invalid IM4P kernel payload")
        // Optional compression record: algorithm 1 is LZFSE, followed by the decoded size.
        var size: Int?
        if let next = fields.next(), next.identifier == .sequence, case .constructed(let record) = next.content {
            var values = record.makeIterator()
            if let algorithm = try? Int(derEncoded: &values), algorithm == 1 { size = try Int(derEncoded: &values) }
        }
        return (Data(payload.bytes), size)
    }
}
