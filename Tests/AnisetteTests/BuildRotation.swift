#if os(macOS) || os(Linux)
import Foundation
import Testing
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
@testable import Anisette

/// Rotates the pinned Apple build with no hand-edited values; run it with `make rotate` (see
/// MAINTAINING.md). ANISETTE_ROTATE names the restore image: "latest" or an IPSW URL. Everything in
/// `Resources/Profile.json` is read or derived from that image, checked by running ADI on the result,
/// and only then written. The extracted assets go to ANISETTE_APPLE_DIR for the test run that follows.
struct BuildRotation {
    static let environment = ProcessInfo.processInfo.environment
    static let catalog = URL(string: "https://mesu.apple.com/assets/macos/com_apple_macOSIPSW/com_apple_macOSIPSW.xml")!
    /// The kernel cache whose FairPlayIOKit the runtime emulates.
    static let kernelCacheName = "kernelcache.release.mac13j"
    static let profileURL = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent().appendingPathComponent("Sources/Anisette/Resources/Profile.json")

    @Test(.enabled(if: environment["ANISETTE_ROTATE"] != nil))
    func rotateBuild() async throws {
        let http = AnisetteHTTPClient.live
        let request = try #require(Self.environment["ANISETTE_ROTATE"])
        let directory = URL(fileURLWithPath: try #require(Self.environment["ANISETTE_APPLE_DIR"]))
        let current = try PinnedBuild.current()
        let url = request == "latest" ? try await Self.latestRestoreImage(http) : try #require(URL(string: request))
        let size = try await Self.contentLength(url)
        let archive = try await RestoreArchive.open(RemoteAssetFile(http: http, url: url, size: size).file)
        func member(_ name: String) throws -> PinnedBuild.Member {
            let entries = archive.entries.filter { $0.name == name }
            try require(entries.count == 1, "Restore image must hold one \(name)")
            return .init(name: name, compressed: entries[0].compressed, size: entries[0].size)
        }

        // The build manifest names the disk images that go with the kernel cache.
        let manifest = try await archive.member(member("BuildManifest.plist"))
        let images = try Self.diskImages(await manifest.read(0, Int(manifest.size)))
        let kernelMember = try member(Self.kernelCacheName)

        var assets: [String: Data] = [:]
        let (systemVolume, systemTree) = try await archive.volume(member(images.system), http: http)
        for path in AssetInstaller.frameworkPaths {
            assets[AssetInstaller.name(path)] = try await AssetInstaller.framework(path, in: systemTree)
        }
        let (cacheVolume, cacheTree) = try await archive.volume(member(images.sharedCache), http: http)
        assets["AppleMediaServices"] = try await DyldAsset().extract(from: cacheTree)
        let collection = try await archive.kernelCollection(kernelMember)
        assets["FairPlayIOKit"] = try MachOExtraction.kernel(collection)
        let kernelBase = try MachO(collection).base

        let system = try await ProfileGeneration.systemInfo(systemTree, kernel: collection)
        let entries = try ProfileGeneration.entries(assets, kernelCollectionBase: kernelBase)
        let tables = try await ProfileGeneration.sharedCacheTables(ProfileGeneration.image("AppleMediaServices", assets),
                                                                   cache: SharedCacheSymbols(cacheTree))
        let pinned = assets.map { PinnedBuild.Asset(name: $0.key, size: $0.value.count, hash: Resources.hash($0.value)) }
            .sorted { $0.name < $1.name }
        var configuration = try Profile.Configuration(
            build: PinnedBuild(
                restoreImageURL: url, restoreImageSize: size,
                system: systemVolume, sharedCache: cacheVolume,
                kernelCache: kernelMember, kernelCollectionBase: kernelBase,
                cacheName: Self.cacheName(system, assets: pinned, current: current), assets: pinned, preparedImageHashes: [:]),
            system: system, entries: entries,
            functions: Dictionary(uniqueKeysWithValues: tables.functions.map { ("\($0.key)", $0.value) }),
            slots: Dictionary(uniqueKeysWithValues: tables.slots.map { ("\($0.key)", $0.value) }))

        // Prove the candidate before writing it: ADI must start and answer an OTP request for an
        // unprovisioned identity with its not-provisioned status.
        let profile = try Profile.load(assets: assets, configuration: configuration)
        let library = try await UnicornArtifact.current.resolve(in: AnisetteConfiguration.defaultCacheDirectory, http: http)
        let runtime = try ADIRuntime(identifier: withUnsafeBytes(of: UUID().uuid) { Data($0) }, state: Data(), profile: profile,
                                     library: UnicornLibrary(url: library), cancellation: Cancellation())
        let error = #expect(throws: AnisetteError.self) { _ = try runtime.requestOTP() }
        try #require(error?.adiStatus == AnisetteError.notProvisionedStatus,
                     "ADI did not run on the new build: \(String(describing: error))")

        for image in profile.images { configuration.build.preparedImageHashes[image.name] = Resources.hash(image.data) }
        for (name, data) in assets { try Resources.writePrivate(data, to: directory.appendingPathComponent(name)) }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        try (encoder.encode(configuration) + Data("\n".utf8)).write(to: Self.profileURL, options: .atomic)
        print("Pinned macOS \(system.productVersion) (\(system.buildVersion)) from \(url.absoluteString)")
    }

    /// The newest release Apple's catalog lists for the virtual Mac, which takes the universal image.
    static func latestRestoreImage(_ http: AnisetteHTTPClient) async throws -> URL {
        var node: Any = try ProfileGeneration.plist(await http.fetch(catalog, nil))
        for key in ["MobileDeviceSoftwareVersionsByVersion", "1", "MobileDeviceSoftwareVersions", "VirtualMac2,1"] {
            node = try #require((node as? [String: Any])?[key], "Apple's catalog has no \(key)")
        }
        let builds = try #require(node as? [String: Any]).compactMap { build, value -> (String, URL)? in
            guard let restore = (value as? [String: Any])?["Restore"] as? [String: Any],
                  let url = (restore["FirmwareURL"] as? String).flatMap(URL.init(string:)) else { return nil }
            return (build, url)
        }
        let latest = builds.max { $0.0.compare($1.0, options: .numeric) == .orderedAscending }
        return try #require(latest, "Apple's catalog lists no restore image").1
    }

    static func contentLength(_ url: URL) async throws -> UInt64 {
        var request = URLRequest(url: url)
        request.httpMethod = "HEAD"
        let response = try await URLSession.shared.data(for: request).1 as? HTTPURLResponse
        let length = response?.value(forHTTPHeaderField: "Content-Length").flatMap { UInt64($0) }
        return try #require(response?.statusCode == 200 ? length : nil, "Cannot read the size of \(url.lastPathComponent)")
    }

    /// The system and SystemOS disk images of the identities that boot `kernelCacheName`.
    static func diskImages(_ manifest: Data) throws -> (system: String, sharedCache: String) {
        let identities = try #require(ProfileGeneration.plist(manifest)["BuildIdentities"] as? [[String: Any]])
        func path(_ identity: [String: Any], _ component: String) -> String? {
            let manifest = identity["Manifest"] as? [String: Any]
            return ((manifest?[component] as? [String: Any])?["Info"] as? [String: Any])?["Path"] as? String
        }
        let matching = identities.filter { path($0, "KernelCache") == kernelCacheName }
        let system = Set(matching.compactMap { path($0, "OS") }), cache = Set(matching.compactMap { path($0, "Cryptex1,SystemOS") })
        try require(system.count == 1 && cache.count == 1, "Build manifest does not name one system and one SystemOS image")
        return (system.first!, cache.first!)
    }

    /// A new build starts at `-v1`; the same build with different extracted bytes takes the next number.
    static func cacheName(_ system: AnisetteSystemInfo, assets: [PinnedBuild.Asset], current: PinnedBuild) throws -> String {
        let major = system.productVersion.prefix { $0 != "." }
        let prefix = "apple-assets-macos-\(major)-\(system.buildVersion)-arm64-v"
        guard current.cacheName.hasPrefix(prefix) else { return prefix + "1" }
        if assets == current.assets.sorted(by: { $0.name < $1.name }) { return current.cacheName }
        let revision = try #require(Int(current.cacheName.dropFirst(prefix.count)))
        return prefix + String(revision + 1)
    }
}
#endif
