import Foundation

/// The pinned Apple build: where its restore image is, which members hold the files the runtime
/// needs, and what the extracted files must hash to. Decoded from `Resources/Profile.json`, which
/// `make rotate` generates from a restore image; see MAINTAINING.md.
struct PinnedBuild: Codable, Sendable {
    struct Member: Codable, Sendable { let name: String; let compressed: UInt64; let size: UInt64 }
    /// An encrypted disk image in the restore archive and the size of the filesystem it decrypts to.
    struct Volume: Codable, Sendable { let member: Member; let filesystemSize: UInt64 }
    struct Asset: Codable, Sendable, Equatable { let name: String; let size: Int; let hash: String }

    let restoreImageURL: URL
    let restoreImageSize: UInt64
    /// The macOS system volume, holding the framework binaries.
    let system: Volume
    /// The SystemOS volume, holding the dyld shared cache.
    let sharedCache: Volume
    let kernelCache: Member
    /// Address the kernel collection's chained pointers are relative to.
    let kernelCollectionBase: UInt64
    /// Directory under the cache root; it changes whenever the extracted bytes do.
    let cacheName: String
    /// Size and SHA-256 of each extracted file. Nothing else is accepted from a download or a cache.
    let assets: [Asset]
    /// SHA-256 of each image as `Profile.load` prepares it, so tests can check relocation without
    /// storing Apple bytes.
    var preparedImageHashes: [String: String]

    static func current() throws -> PinnedBuild { try Profile.Configuration.load().build }
}
