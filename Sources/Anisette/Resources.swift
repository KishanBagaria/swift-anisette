import Foundation
import Crypto

struct Resources: Sendable {
    let profile: Profile
    let library: URL

    static func hash(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }

    static func verify(_ data: Data, size: Int? = nil, hash expected: String) -> Bool {
        (size.map { data.count == $0 } ?? true) && hash(data) == expected
    }

    static func writePrivate(_ data: Data, to url: URL) throws {
        let manager = FileManager.default
        try manager.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true,
                                    attributes: [.posixPermissions: 0o700])
        try data.write(to: url, options: .atomic)
        try manager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    /// Verifying the ~78 MB of assets is expensive, so do it once per configuration per process.
    static func load(configuration: AnisetteConfiguration) async throws -> Resources {
        try await Cache.shared.load(configuration)
    }

    private actor Cache {
        /// Loaded resources depend only on these locations: every byte is verified
        /// against pinned hashes, whichever HTTP client fetched it.
        struct Key: Hashable {
            let appleDirectory: URL?
            let unicornLibrary: URL?
            let cacheDirectory: URL
        }
        static let shared = Cache()
        private var loads: [Key: Task<Resources, Error>] = [:]

        func load(_ configuration: AnisetteConfiguration) async throws -> Resources {
            let key = Key(appleDirectory: configuration.appleDirectory, unicornLibrary: configuration.unicornLibrary,
                          cacheDirectory: configuration.cacheDirectory)
            if let existing = loads[key] { return try await existing.value }
            let task = Task { try await Resources.loadUncached(configuration: configuration) }
            loads[key] = task
            do {
                return try await task.value
            } catch {
                loads[key] = nil
                throw error
            }
        }
    }

    private static func loadUncached(configuration: AnisetteConfiguration) async throws -> Resources {
        let assets: [String: Data]
        if let explicit = configuration.appleDirectory {
            assets = try readAssets(explicit)
        } else {
            let native = try configuration.cacheDirectory.appendingPathComponent(PinnedBuild.current().cacheName)
            if let existing = try? readAssets(native) { assets = existing } else {
                try await AssetInstaller.shared.install(in: native, http: configuration.httpClient)
                assets = try readAssets(native)
            }
        }
        let library: URL
        if let explicit = configuration.unicornLibrary { library = explicit } else {
            library = try await UnicornArtifact.current.resolve(in: configuration.cacheDirectory, http: configuration.httpClient)
        }
        return Resources(profile: try Profile.load(assets: assets), library: library)
    }

    static func readAssets(_ directory: URL) throws -> [String: Data] {
        var assets: [String: Data] = [:]
        for file in try PinnedBuild.current().assets {
            let data = try Data(contentsOf: directory.appendingPathComponent(file.name), options: .mappedIfSafe)
            try require(verify(data, size: file.size, hash: file.hash), "Apple asset \(file.name) failed integrity verification")
            assets[file.name] = data
        }
        return assets
    }
}
