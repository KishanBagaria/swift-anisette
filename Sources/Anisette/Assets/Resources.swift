import Foundation
import Crypto
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#endif

struct Resources: Sendable {
    static let lastUsedFileName = ".last-used"
    static let defaultPruneMaxAge: TimeInterval = 14 * 24 * 60 * 60
    static let defaultKeepRecent = 2

    /// The resolved backend, carrying the Unicorn library it runs on when applicable.
    enum Engine: Hashable, Sendable {
        /// This host's hardware-virtualization backend (`Resources.nativeBackend`).
        case native
        case unicorn(URL)

        /// Loads the backend once; the returned closure creates engines that share it.
        func factory(
            cancellation: Cancellation,
            loadLibrary: (URL) throws -> UnicornLibrary = { try UnicornLibrary(url: $0) }
        ) throws -> () throws -> any GuestEngine {
            switch self {
            case .unicorn(let url):
                let library = try loadLibrary(url)
                return { try Unicorn(library: library, cancellation: cancellation) }
            case .native:
                let makeEngine = try nativeEngineMaker()
                return { try makeEngine(cancellation) }
            }
        }
    }

    /// This host's hardware-virtualization backend, if it has one.
    #if arch(arm64) && os(macOS)
    static let nativeBackend: AnisetteConfiguration.Backend? = .hypervisor
    #elseif arch(arm64) && os(Linux)
    static let nativeBackend: AnisetteConfiguration.Backend? = .kvm
    #else
    static let nativeBackend: AnisetteConfiguration.Backend? = nil
    #endif

    /// Whether this host has a hardware-virtualization backend whose VM can be created.
    static var isNativeAvailable: Bool {
        #if arch(arm64) && (os(macOS) || os(Linux))
        NativeRuntime.isAvailable
        #else
        false
        #endif
    }

    /// Loads the shared native VM and returns a maker for its engines.
    private static func nativeEngineMaker() throws -> (Cancellation) throws -> any GuestEngine {
        #if arch(arm64) && (os(macOS) || os(Linux))
        let runtime = try NativeRuntime.shared()
        return { try ARM64Engine(runtime: runtime, cancellation: $0) }
        #else
        throw AnisetteError("This host has no hardware-virtualization backend")
        #endif
    }

    let profile: Profile
    let engine: Engine

    private static let cache = Coalescer<CacheKey, Resources>()

    static func hash(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }

    static func verify(_ data: Data, size: Int? = nil, hash expected: String) -> Bool {
        (size.map { data.count == $0 } ?? true) && hash(data) == expected
    }

    static func writePrivate(_ data: Data, to url: URL) throws {
        let manager = FileManager.default
        let directory = url.deletingLastPathComponent()
        try manager.createDirectory(at: directory, withIntermediateDirectories: true,
                                    attributes: [.posixPermissions: 0o700])
        try manager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
        let tempPath = directory.appendingPathComponent(".\(url.lastPathComponent).\(UUID().uuidString).tmp").path
        let destinationPath = url.path
        let fd = open(tempPath, O_WRONLY | O_CREAT | O_EXCL, mode_t(0o600))
        guard fd >= 0 else {
            throw AnisetteError("Cannot create \(url.lastPathComponent): \(String(cString: strerror(errno)))")
        }
        var closed = false
        do {
            guard fchmod(fd, mode_t(0o600)) == 0 else {
                throw AnisetteError("Cannot secure \(url.lastPathComponent): \(String(cString: strerror(errno)))")
            }
            try writeAll(data, to: fd, name: url.lastPathComponent)
            guard close(fd) == 0 else {
                closed = true
                throw AnisetteError("Cannot close \(url.lastPathComponent): \(String(cString: strerror(errno)))")
            }
            closed = true
            guard rename(tempPath, destinationPath) == 0 else {
                throw AnisetteError("Cannot replace \(url.lastPathComponent): \(String(cString: strerror(errno)))")
            }
        } catch {
            if !closed { _ = close(fd) }
            _ = unlink(tempPath)
            throw error
        }
    }

    private static func writeAll(_ data: Data, to fd: Int32, name: String) throws {
        try data.withUnsafeBytes { buffer in
            guard let base = buffer.baseAddress else { return }
            var written = 0
            while written < buffer.count {
                let count = write(fd, base.advanced(by: written), buffer.count - written)
                if count < 0 {
                    if errno == EINTR { continue }
                    throw AnisetteError("Cannot write \(name): \(String(cString: strerror(errno)))")
                }
                if count == 0 {
                    throw AnisetteError("Short write for \(name)")
                }
                written += count
            }
        }
    }

    /// Whether `requested` runs on the native backend; throws if it names one this host cannot run.
    static func usesNativeBackend(_ requested: AnisetteConfiguration.Backend) throws -> Bool {
        switch requested {
        case .unicorn:
            return false
        case .automatic:
            return isNativeAvailable
        case .hypervisor, .kvm:
            guard requested == nativeBackend else {
                throw requested == .kvm
                    ? AnisetteError("KVM backend is only supported on ARM64 Linux")
                    : AnisetteError("Hypervisor backend is only supported on Apple Silicon macOS")
            }
            _ = try nativeEngineMaker()
            return true
        }
    }

    /// Verifying the ~78 MB of assets is expensive, so do it once per configuration per process.
    static func load(configuration: AnisetteConfiguration) async throws -> Resources {
        let native = try usesNativeBackend(configuration.backend)
        let key = CacheKey(
            appleDirectory: configuration.appleDirectory,
            unicornLibrary: native ? nil : configuration.unicornLibrary,
            cacheDirectory: configuration.cacheDirectory,
            native: native
        )
        return try await cache.load(key) {
            try await Resources.loadUncached(configuration: configuration, native: native)
        }
    }

    /// Loaded resources depend only on these locations and execution backend: every byte is
    /// verified against pinned hashes, whichever HTTP client fetched it.
    struct CacheKey: Hashable, Sendable {
        let appleDirectory: URL?
        let unicornLibrary: URL?
        let cacheDirectory: URL
        let native: Bool
    }

    private static func loadUncached(configuration: AnisetteConfiguration, native: Bool) async throws -> Resources {
        let build = try PinnedBuild.current()
        async let assetsResult = loadAssets(for: build, configuration: configuration)
        async let unicornResult: (URL?, String?, Bool) = native
            ? (nil, nil, false)
            : loadUnicorn(configuration: configuration)
        let (assets, activeAssetDirectory, installedAssets) = try await assetsResult
        let (library, activeUnicornPath, installedUnicorn) = try await unicornResult
        let profile = try Profile.load(assets: assets)
        if let activeAssetDirectory { touchLastUsed(in: activeAssetDirectory) }
        if let library, activeUnicornPath != nil { touchLastUsed(in: library.deletingLastPathComponent()) }
        if installedAssets || installedUnicorn {
            pruneCache(
                in: configuration.cacheDirectory,
                keepingAssetFolder: activeAssetDirectory?.lastPathComponent,
                keepingUnicornPath: activeUnicornPath
            )
        }
        return Resources(profile: profile, engine: library.map(Engine.unicorn) ?? .native)
    }

    private static func loadAssets(
        for build: PinnedBuild,
        configuration: AnisetteConfiguration
    ) async throws -> ([String: Data], URL?, Bool) {
        if let explicit = configuration.appleDirectory {
            do { return (try readAssets(explicit), nil, false) } catch let error as AnisetteError {
                throw AnisetteError("\(error). appleDirectory must hold the assets of the pinned build "
                    + "\(build.cacheName); install them again, or leave it unset to download them")
            }
        }
        let native = configuration.cacheDirectory.appendingPathComponent(build.cacheName)
        if let existing = try? readAssets(native) { return (existing, native, false) }
        try await AssetInstaller.shared.install(in: native, http: configuration.httpClient)
        return (try readAssets(native), native, true)
    }

    private static func loadUnicorn(configuration: AnisetteConfiguration) async throws -> (URL, String?, Bool) {
        if let explicit = configuration.unicornLibrary { return (explicit, nil, false) }
        let artifact = UnicornArtifact.current
        let (library, installed) = try await artifact.resolve(in: configuration.cacheDirectory, http: configuration.httpClient)
        return (library, artifact.relativePath, installed)
    }

    static func touchLastUsed(in directory: URL, now: Date = Date()) {
        let manager = FileManager.default
        let type = (try? manager.attributesOfItem(atPath: directory.path)[.type]) as? FileAttributeType
        guard type == .typeDirectory else { return }
        let marker = directory.appendingPathComponent(lastUsedFileName)
        if !manager.fileExists(atPath: marker.path) {
            try? writePrivate(Data(), to: marker)
        }
        try? manager.setAttributes([.modificationDate: now], ofItemAtPath: marker.path)
    }

    static func pruneCache(
        in cacheDirectory: URL,
        keepingAssetFolder activeAssetFolder: String?,
        keepingUnicornPath activeUnicornPath: String?,
        maxAge: TimeInterval = defaultPruneMaxAge,
        keepRecent: Int = defaultKeepRecent,
        now: Date = Date()
    ) {
        if let activeAssetFolder {
            let assetDirectories = childDirectories(in: cacheDirectory).filter { $0.lastPathComponent.hasPrefix("apple-assets-") }
            pruneDirectories(
                assetDirectories,
                isActive: { $0.lastPathComponent == activeAssetFolder },
                maxAge: maxAge,
                keepRecent: keepRecent,
                now: now
            )
        }
        if let activeUnicornPath {
            pruneUnicorn(
                in: cacheDirectory,
                keepingUnicornPath: activeUnicornPath,
                maxAge: maxAge,
                keepRecent: keepRecent,
                now: now
            )
        }
    }

    private static func pruneUnicorn(
        in cacheDirectory: URL,
        keepingUnicornPath activePath: String,
        maxAge: TimeInterval,
        keepRecent: Int,
        now: Date
    ) {
        let unicornRoot = cacheDirectory.appendingPathComponent("unicorn")
        let versions = childDirectories(in: unicornRoot)
        var candidates: [URL] = []
        var containerVersions: [URL] = []
        for version in versions {
            let hashes = childDirectories(in: version)
            if hashes.isEmpty {
                candidates.append(version)
            } else {
                candidates.append(contentsOf: hashes)
                containerVersions.append(version)
            }
        }
        let activeResolved = cacheDirectory.appendingPathComponent(activePath).standardizedFileURL.path
        pruneDirectories(
            candidates,
            isActive: { url in
                let path = url.standardizedFileURL.path
                return activeResolved == path || activeResolved.hasPrefix(path + "/")
            },
            maxAge: maxAge,
            keepRecent: keepRecent,
            now: now
        )
        for version in containerVersions {
            let remaining = (try? FileManager.default.contentsOfDirectory(atPath: version.path)) ?? []
            if remaining.allSatisfy({ $0 == lastUsedFileName }) {
                try? FileManager.default.removeItem(at: version)
            }
        }
    }

    private static func pruneDirectories(
        _ candidates: [URL],
        isActive: (URL) -> Bool,
        maxAge: TimeInterval,
        keepRecent: Int,
        now: Date
    ) {
        let sorted = candidates
            .map { (url: $0, date: lastUsedDate(for: $0)) }
            .sorted { lhs, rhs in
                if lhs.date != rhs.date { return lhs.date > rhs.date }
                return lhs.url.lastPathComponent > rhs.url.lastPathComponent
            }
        let keepCount = max(0, keepRecent)
        for (index, item) in sorted.enumerated() {
            if isActive(item.url) || index < keepCount { continue }
            if now.timeIntervalSince(item.date) > maxAge {
                try? FileManager.default.removeItem(at: item.url)
            }
        }
    }

    private static func childDirectories(in directory: URL) -> [URL] {
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: directory.path) else { return [] }
        return names.compactMap { name in
            let url = directory.appendingPathComponent(name)
            let type = (try? FileManager.default.attributesOfItem(atPath: url.path)[.type]) as? FileAttributeType
            return type == .typeDirectory ? url : nil
        }
    }

    private static func lastUsedDate(for directory: URL) -> Date {
        let manager = FileManager.default
        let marker = directory.appendingPathComponent(lastUsedFileName)
        if let date = (try? manager.attributesOfItem(atPath: marker.path)[.modificationDate]) as? Date {
            return date
        }
        if let date = (try? manager.attributesOfItem(atPath: directory.path)[.modificationDate]) as? Date {
            return date
        }
        return .distantFuture
    }

    static func readAssets(_ directory: URL) throws -> [String: Data] {
        var assets: [String: Data] = [:]
        for file in try PinnedBuild.current().assets {
            guard let data = try? Data(contentsOf: directory.appendingPathComponent(file.name), options: .mappedIfSafe) else {
                throw AnisetteError("Apple asset \(file.name) is missing from \(directory.path)")
            }
            try require(verify(data, size: file.size, hash: file.hash),
                        "Apple asset \(file.name) in \(directory.path) failed integrity verification")
            assets[file.name] = data
        }
        return assets
    }
}
