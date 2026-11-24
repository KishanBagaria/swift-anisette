import Foundation

/// Configuration for the verified data and native Unicorn library used by Anisette.
/// Set either URL to use an offline installation rather than the default cache.
public struct AnisetteConfiguration: Sendable {
    /// Directory containing verified Apple assets for offline use; when `nil`, assets are cached in `cacheDirectory`.
    public var appleDirectory: URL?
    /// Path to a preinstalled `libunicorn` shared library; when `nil`, the pinned wheel is cached in `cacheDirectory`.
    public var unicornLibrary: URL?
    /// Directory used to cache downloaded Apple assets and the Unicorn runtime.
    public var cacheDirectory: URL
    /// Performs the first-use downloads. Everything it returns is verified against pinned hashes.
    public var httpClient: AnisetteHTTPClient

    /// Download cache; Linux honors an absolute `XDG_CACHE_HOME`.
    public static var defaultCacheDirectory: URL {
        #if os(Linux)
        let path = ProcessInfo.processInfo.environment["XDG_CACHE_HOME"]
        let root = path.flatMap { ($0 as NSString).isAbsolutePath ? URL(fileURLWithPath: $0) : nil }
            ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".cache")
        #else
        let root = URL.cachesDirectory
        #endif
        return root.appendingPathComponent("swift-anisette")
    }

    /// Creates a configuration for locating or downloading Apple assets and the Unicorn library.
    public init(
        appleDirectory: URL? = nil,
        unicornLibrary: URL? = nil,
        cacheDirectory: URL = Self.defaultCacheDirectory,
        httpClient: AnisetteHTTPClient = .live
    ) {
        self.appleDirectory = appleDirectory
        self.unicornLibrary = unicornLibrary
        self.cacheDirectory = cacheDirectory
        self.httpClient = httpClient
    }
}

/// A local virtual Mac identity. Apple code runs inside Unicorn; host files,
/// processes, Keychain, and credentials are never exposed to the guest.
public final class AnisetteContext: Sendable {
    /// Finishing provisioning ends ADI's runtime, so `provisioned` is terminal like `closed`.
    private enum Phase { case ready(ADIRuntime), provisioning(ADIRuntime, session: UInt32), provisioned, closed }
    private final class State: @unchecked Sendable {
        // Accessed exclusively on Worker.queue, including destruction.
        var phase = Phase.closed
    }
    private let state = State()
    private let cancellation: Cancellation

    private init(cancellation: Cancellation) { self.cancellation = cancellation }

    deinit {
        let state = state
        Worker.shared.queue.async { state.phase = .closed }
    }

    /// Downloads, verifies, and caches the Apple assets and Unicorn runtime for `configuration`
    /// without opening a context.
    public static func prepare(configuration: AnisetteConfiguration = AnisetteConfiguration()) async throws {
        _ = try await Resources.load(configuration: configuration)
    }

    /// Opens a virtual Mac context for `identifier`, optionally restoring a previously persisted
    /// `provisioningState`. Call `close()` when finished, or use `with(identifier:provisioningState:configuration:_:)`
    /// to scope the lifetime automatically.
    public static func open(
        identifier: UUID,
        provisioningState: Data = Data(),
        configuration: AnisetteConfiguration = AnisetteConfiguration()
    ) async throws -> AnisetteContext {
        let resources = try await Resources.load(configuration: configuration)
        let cancellation = try Cancellation()
        let context = AnisetteContext(cancellation: cancellation)
        let bytes = withUnsafeBytes(of: identifier.uuid) { Data($0) }
        try await context.perform {
            let library = try Worker.shared.library(at: resources.library)
            context.state.phase = .ready(try ADIRuntime(identifier: bytes, state: provisioningState, profile: resources.profile,
                                                        library: library, cancellation: cancellation))
        }
        return context
    }

    /// Opens a context, runs `body`, and closes the context when `body`
    /// returns, throws, or is cancelled. Do not let the context escape `body`.
    public static func with<T>(
        identifier: UUID,
        provisioningState: Data = Data(),
        configuration: AnisetteConfiguration = AnisetteConfiguration(),
        isolation: isolated (any Actor)? = #isolation,
        _ body: (AnisetteContext) async throws -> sending T
    ) async throws -> sending T {
        let context = try await open(identifier: identifier, provisioningState: provisioningState,
                                     configuration: configuration)
        do {
            let value = try await body(context)
            await context.close()
            return value
        } catch {
            await context.close()
            throw error
        }
    }

    /// Provisions a new virtual Mac identity in a dedicated context, passing the client challenge
    /// (`cpim`) to `exchange` and finishing with Apple's reply (`ptm` and `tk`).
    public static func provision(
        identifier: UUID,
        challenge: Data,
        configuration: AnisetteConfiguration = AnisetteConfiguration(),
        isolation: isolated (any Actor)? = #isolation,
        exchange: (_ clientChallenge: Data) async throws -> (metadata: Data, trustKey: Data)
    ) async throws -> Data {
        try await provision(
            identifier: identifier,
            configuration: configuration,
            isolation: isolation,
            start: { try await $0.startProvisioning(challenge: challenge) },
            exchange: exchange
        )
    }

    static func provision(
        identifier: UUID,
        configuration: AnisetteConfiguration,
        isolation: isolated (any Actor)? = #isolation,
        start: (AnisetteContext) async throws -> ProvisioningSession,
        exchange: (_ clientChallenge: Data) async throws -> (metadata: Data, trustKey: Data)
    ) async throws -> Data {
        try await with(identifier: identifier, configuration: configuration, isolation: isolation) { context in
            let session = try await start(context)
            let (metadata, trustKey) = try await exchange(session.clientChallenge)
            return try await session.finish(metadata: metadata, trustKey: trustKey)
        }
    }

    /// An exchange begun by `startProvisioning(challenge:)`. Send `clientChallenge` to Apple, then pass
    /// its reply to `finish(metadata:trustKey:)`. To abandon the exchange, close the context.
    public struct ProvisioningSession: Sendable {
        /// The client's provisioning data (Apple's `cpim`) to send to Apple's provisioning service.
        public let clientChallenge: Data
        let context: AnisetteContext

        /// Completes provisioning with Apple's reply (`ptm` and `tk`) and returns the identity's new
        /// provisioning state, which the caller must persist.
        ///
        /// This finishes the context whether it succeeds or throws: ADI's runtime is torn down, and every
        /// later call on the context throws `AnisetteError` (with `adiStatus == nil`), or
        /// `CancellationError` once it is closed. Request OTPs from a new context opened with the
        /// returned state; after a failure, start over in a new context.
        public func finish(metadata: Data, trustKey: Data) async throws -> Data {
            try await context.finishProvisioning(metadata: metadata, trustKey: trustKey)
        }
    }

    /// Begins provisioning with Apple's server challenge (`spim`). Only one exchange can be in progress,
    /// and `requestOTP()` throws until it finishes. If ADI rejects the challenge, `adiStatus` holds its
    /// status and the context remains usable.
    public func startProvisioning(challenge: Data) async throws -> ProvisioningSession {
        let clientChallenge = try await perform {
            let runtime = try self.readyRuntime()
            let (session, clientChallenge) = try runtime.startProvisioning(challenge)
            self.state.phase = .provisioning(runtime, session: session)
            return clientChallenge
        }
        return ProvisioningSession(clientChallenge: clientChallenge, context: self)
    }

    private func finishProvisioning(metadata: Data, trustKey: Data) async throws -> Data {
        try await perform {
            guard case .provisioning(let runtime, let session) = self.state.phase else {
                _ = try self.readyRuntime() // Reports a finished or closed context; a ready one has no session.
                throw AnisetteError("No provisioning session is in progress")
            }
            self.state.phase = .provisioned
            return try runtime.endProvisioning(session: session, ptm: metadata, tk: trustKey)
        }
    }

    /// An anisette one-time password returned by `AnisetteContext.requestOTP()`.
    public struct OTP: Sendable, Equatable, Hashable {
        /// The identity's machine ID (`X-Apple-I-MD-M`, before base64 encoding).
        public let machineID: Data
        /// The one-time password (`X-Apple-I-MD`, before base64 encoding).
        public let password: Data
        /// Updated provisioning state that the caller must persist before the next request.
        public let provisioningState: Data
    }

    /// Requests a new one-time password and updated provisioning state for this identity.
    /// Throws `AnisetteError` with `adiStatus == AnisetteError.notProvisionedStatus` for an
    /// identity that has not been provisioned.
    public func requestOTP() async throws -> OTP {
        try await perform {
            let (machineID, password, state) = try self.readyRuntime().requestOTP()
            return OTP(machineID: machineID, password: password, provisioningState: state)
        }
    }

    /// The runtime when no provisioning exchange is in progress. Called on Worker.queue.
    private func readyRuntime() throws -> ADIRuntime {
        switch state.phase {
        case .ready(let runtime): return runtime
        case .provisioning: throw AnisetteError("A provisioning session is in progress")
        case .provisioned: throw AnisetteError("Provisioning finished this context; open a new one with the returned state")
        case .closed: throw CancellationError()
        }
    }

    /// Cancels any active operation and tears down the underlying Unicorn engines. Safe to call multiple times.
    public func close() async {
        cancellation.cancel()
        let state = state
        await withCheckedContinuation { continuation in
            Worker.shared.queue.async { state.phase = .closed; continuation.resume() }
        }
    }

    func isClosed() async -> Bool {
        let state = state
        return await withCheckedContinuation { continuation in
            Worker.shared.queue.async {
                let closed: Bool
                if case .closed = state.phase { closed = true } else { closed = false }
                continuation.resume(returning: closed)
            }
        }
    }

    private func perform<T: Sendable>(_ operation: @escaping @Sendable () throws -> T) async throws -> T {
        try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                Worker.shared.queue.async {
                    continuation.resume(with: Result {
                        try self.cancellation.check()
                        let value = try operation()
                        try self.cancellation.check()
                        return value
                    })
                }
            }
        } onCancel: {
            self.cancellation.cancel()
            let state = self.state
            Worker.shared.queue.async { state.phase = .closed }
        }
    }
}

private final class Worker: @unchecked Sendable {
    static let shared = Worker()
    // Unicorn's global clock initialization must not overlap another engine's execution.
    let queue = DispatchQueue(label: "swift-anisette.worker", qos: .userInitiated)
    private var libraries: [URL: UnicornLibrary] = [:]

    func library(at url: URL) throws -> UnicornLibrary {
        let key = url.standardizedFileURL
        let library = try libraries[key] ?? UnicornLibrary(url: key)
        libraries[key] = library
        return library
    }
}
