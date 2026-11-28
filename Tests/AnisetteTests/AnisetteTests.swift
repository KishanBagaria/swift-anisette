#if os(macOS) || os(Linux)
import Foundation
import Testing
@testable import Anisette

@Suite(.serialized)
struct AnisetteTests {
    @Test func guestAddressOverflowIsRecoverable() throws {
        #expect(try guestAddress(UInt64.max - 8, offset: 8) == UInt64.max)
        #expect(throws: (any Error).self) { try guestAddress(UInt64.max, offset: 8) }
        #expect(throws: (any Error).self) { try guestAligned(UInt64.max) }
        #expect(try guestAligned(17) == 32)
    }

    @Test func virtualFileReadsSlicedData() throws {
        let sliced = Data([9, 1, 2, 3]).dropFirst()
        #expect(sliced.startIndex != 0)
        #expect(try sliced.virtualFileBytes(offset: 0, count: 2) == Data([1, 2]))
        #expect(try sliced.virtualFileBytes(offset: 2, count: 5) == Data([3]))
        #expect(try sliced.virtualFileBytes(offset: 3, count: 5).isEmpty)
        #expect(throws: (any Error).self) { try sliced.virtualFileBytes(offset: 4, count: 1) }
    }

    @Test func lzfseDecodesStoredBlocksAndRejectsTruncation() throws {
        let payload = Data("test native decompression".utf8)
        let stream = Data("bvx-".utf8) + Data.littleEndian(UInt32(payload.count)) + payload + Data("bvx$".utf8)
        #expect(try stream.lzfseDecoded(size: payload.count) == payload)
        #expect(throws: (any Error).self) { try Data(stream.prefix(10)).lzfseDecoded(size: payload.count) }
        #expect(throws: (any Error).self) { try stream.lzfseDecoded(size: payload.count - 1) }
        #expect(throws: (any Error).self) { try Data(stream.dropLast(4)).lzfseDecoded(size: payload.count) }
    }

    @Test func rawLZVNRequiresCompleteStreamAndAllowsTrailingBytes() throws {
        let payload = Data("hello".utf8)
        // Small literal opcode, five literal bytes, and the eight-byte EOS opcode.
        let stream = Data([0xe5]) + payload + Data([0x06]) + Data(count: 7)
        #expect(try stream.lzfseDecoded(size: payload.count, lzvn: true) == payload)
        #expect(try (stream + Data(count: 32)).lzfseDecoded(size: payload.count, lzvn: true) == payload)
        #expect(try (stream + Data([0xff, 0x12, 0x34])).lzfseDecoded(size: payload.count, lzvn: true) == payload)
        #expect(throws: (any Error).self) { try Data(stream.dropLast()).lzfseDecoded(size: payload.count, lzvn: true) }
        #expect(throws: (any Error).self) { try stream.lzfseDecoded(size: payload.count - 1, lzvn: true) }
        #expect(throws: (any Error).self) { try stream.lzfseDecoded(size: payload.count + 1, lzvn: true) }
    }

    @Test(arguments: [false, true])
    func unicornArchiveChecksBoundaries(compressed: Bool) throws {
        // Independent stored/deflated fixtures produced by Python's zipfile module.
        let encoded = compressed
            ? "UEsDBBQAAAAIAAAAIVA0m8ISFgAAABQAAAADAAAAbGliy0ssySxLVcjJTCpKLKpUSKosSS0GAFBLAQIUAxQAAAAIAAAAIVA0m8IS"
                + "FgAAABQAAAADAAAAAAAAAAAAAACAAQAAAABsaWJQSwUGAAAAAAEAAQAxAAAANwAAAAAA"
            : "UEsDBBQAAAAAAAAAIVA0m8ISFAAAABQAAAADAAAAbGlibmF0aXZlIGxpYnJhcnkgYnl0ZXNQSwECFAMUAAAAAAAAACFQNJvCEhQAAAAU"
                + "AAAAAwAAAAAAAAAAAAAAgAEAAAAAbGliUEsFBgAAAAABAAEAMQAAADUAAAAAAA=="
        let zip = try #require(Data(base64Encoded: encoded))
        let payload = Data("native library bytes".utf8)
        #expect(try UnicornArtifact.member("lib", in: zip) == payload)
        #expect(try UnicornArtifact.member("lib", in: (Data([0]) + zip).dropFirst()) == payload) // Non-zero start index.
        #expect(throws: (any Error).self) { try UnicornArtifact.member("other/lib", in: zip) }
        #expect(throws: (any Error).self) { try UnicornArtifact.member("lib", in: Data(zip.dropLast(5))) }
        var corrupted = zip
        corrupted[33] ^= 0xff
        #expect(throws: (any Error).self) { try UnicornArtifact.member("lib", in: corrupted) }
        let directory = compressed ? 55 : 53
        var oversized = zip
        try oversized.put(UInt32.max, at: directory + 24)
        #expect(throws: (any Error).self) { try UnicornArtifact.member("lib", in: oversized) }
        var undersized = zip
        try undersized.put(UInt32(payload.count - 1), at: directory + 24)
        #expect(throws: (any Error).self) { try UnicornArtifact.member("lib", in: undersized) }
        var symlink = zip
        try symlink.put(UInt32(0o120777) << 16, at: directory + 38)
        #expect(throws: (any Error).self) { try UnicornArtifact.member("lib", in: symlink) }
        var invalidDirectory = zip
        try invalidDirectory.put(UInt32.max, at: zip.count - 6)
        #expect(throws: (any Error).self) { try UnicornArtifact.member("lib", in: invalidDirectory) }
    }

    @Test(.enabled(if: ProcessInfo.processInfo.environment["ANISETTE_TEST_UNICORN"] == "1"))
    func nativeUnicornArchiveDownload() async throws {
        let artifact = UnicornArtifact.current
        let archive = try await AnisetteHTTPClient.live.fetch(artifact.url, nil)
        #expect(Resources.hash(archive) == artifact.archiveHash)
        let library = try UnicornArtifact.member(artifact.member, in: archive)
        #expect(Resources.hash(library) == artifact.libraryHash)
    }

    @Test func cancellationFlagIsExplicitAndSticky() throws {
        let cancellation = try Cancellation()
        try cancellation.check()
        cancellation.cancel()
        #expect(throws: CancellationError.self) { try cancellation.check() }
    }

    @Test(.enabled(if: ProcessInfo.processInfo.environment["ANISETTE_TEST_ASSETS"] == "1"))
    func nativeAssetInstallation() async throws {
        // Installs into ANISETTE_APPLE_DIR when set so the cached-runtime tests can reuse it.
        // Opening the context also installs Unicorn into the default cache, which CI caches with the assets.
        let explicit = Self.environment["ANISETTE_APPLE_DIR"].map { URL(fileURLWithPath: $0) }
        let directory = explicit ?? FileManager.default.temporaryDirectory.appendingPathComponent("anisette-assets-\(UUID())")
        defer { if explicit == nil { try? FileManager.default.removeItem(at: directory) } }
        try await AssetInstaller.shared.install(in: directory, http: .live)
        let context = try await AnisetteContext.open(identifier: UUID(), configuration: .init(appleDirectory: directory))
        await context.close()
        _ = try Resources.readAssets(directory)
    }

    static let environment = ProcessInfo.processInfo.environment

    /// Fails any download, so a test cannot reach the network by accident.
    static let offline = AnisetteHTTPClient { url, _ in
        throw AnisetteError("Unexpected download of \(url.lastPathComponent) in an offline test")
    }

    /// Permits only the pinned, hash-verified Unicorn wheel for this host. A fresh checkout can then run
    /// the cached-runtime tests with only Apple assets present, and nothing else can be fetched.
    static let unicornOnly = AnisetteHTTPClient { url, range in
        guard url == UnicornArtifact.current.url, range == nil else { return try await offline.fetch(url, range) }
        return try await AnisetteHTTPClient.live.fetch(url, nil)
    }

    /// ANISETTE_APPLE_DIR and, if set, ANISETTE_UNICORN_LIBRARY. Apple assets are never fetched;
    /// the Unicorn wheel is downloaded only when no library is named and none is cached.
    static var cachedRuntime: AnisetteConfiguration {
        AnisetteConfiguration(
            appleDirectory: environment["ANISETTE_APPLE_DIR"].map { URL(fileURLWithPath: $0) },
            unicornLibrary: environment["ANISETTE_UNICORN_LIBRARY"].map { URL(fileURLWithPath: $0) },
            httpClient: unicornOnly)
    }

    /// Exercises the commerce, adid, fairplayd, and FairPlayIOKit RPC path without Apple servers.
    @Test(.enabled(if: environment["ANISETTE_APPLE_DIR"] != nil))
    func unprovisionedOTPRequestFails() async throws {
        let context = try await AnisetteContext.open(identifier: UUID(), configuration: Self.cachedRuntime)
        let error = await #expect(throws: AnisetteError.self) { try await context.requestOTP() }
        await context.close()
        #expect(error?.adiStatus == AnisetteError.notProvisionedStatus)
    }

    /// ADI parses and rejects a malformed challenge, leaving the context usable, including for another start.
    @Test(.enabled(if: environment["ANISETTE_APPLE_DIR"] != nil))
    func malformedProvisioningChallengeFails() async throws {
        let context = try await AnisetteContext.open(identifier: UUID(), configuration: Self.cachedRuntime)
        let error = await #expect(throws: AnisetteError.self) {
            try await context.startProvisioning(challenge: Data(count: 256))
        }
        let otpError = await #expect(throws: AnisetteError.self) { try await context.requestOTP() }
        let retryError = await #expect(throws: AnisetteError.self) {
            try await context.startProvisioning(challenge: Data(count: 256))
        }
        // Rejected before reaching ADI.
        for challenge in [Data(), Data(count: (1 << 20) + 1)] {
            let invalid = await #expect(throws: AnisetteError.self) { try await context.startProvisioning(challenge: challenge) }
            #expect(invalid != nil && invalid?.adiStatus == nil)
        }
        await context.close()
        #expect(error?.adiStatus == -45031)
        #expect(otpError?.adiStatus == AnisetteError.notProvisionedStatus)
        #expect(retryError?.adiStatus == -45031)
        await #expect(throws: CancellationError.self) { try await context.startProvisioning(challenge: Data(count: 256)) }
    }

    /// A real session needs Apple's challenge, so this drives `finish` with a session the context never
    /// started: it must neither reach ADI nor end the context.
    @Test(.enabled(if: environment["ANISETTE_APPLE_DIR"] != nil))
    func finishingWithoutAStartedSessionFails() async throws {
        let context = try await AnisetteContext.open(identifier: UUID(), configuration: Self.cachedRuntime)
        let session = AnisetteContext.ProvisioningSession(clientChallenge: Data(), context: context)
        let error = await #expect(throws: AnisetteError.self) {
            try await session.finish(metadata: Data(count: 16), trustKey: Data(count: 16))
        }
        #expect(error?.description == "No provisioning session is in progress")
        let otpError = await #expect(throws: AnisetteError.self) { try await context.requestOTP() }
        #expect(otpError?.adiStatus == AnisetteError.notProvisionedStatus)
        await context.close()
        await #expect(throws: CancellationError.self) {
            try await session.finish(metadata: Data(count: 16), trustKey: Data(count: 16))
        }
    }

    @Test func scopedContextPropagatesOpenFailureWithoutRunningBody() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("anisette-missing-\(UUID())")
        var ran = false
        let configuration = AnisetteConfiguration(appleDirectory: directory, httpClient: Self.offline)
        await #expect(throws: (any Error).self) {
            try await AnisetteContext.with(identifier: UUID(), configuration: configuration) { _ in ran = true }
        }
        #expect(!ran)
    }

    @Test(.enabled(if: environment["ANISETTE_APPLE_DIR"] != nil))
    func scopedContextClosesOnReturnAndThrow() async throws {
        struct Failure: Error {}
        let configuration = Self.cachedRuntime
        var escaped: AnisetteContext?
        let value = try await AnisetteContext.with(identifier: UUID(), configuration: configuration) { context in
            escaped = context
            return 42
        }
        #expect(value == 42)
        let returned = try #require(escaped)
        await #expect(throws: CancellationError.self) { try await returned.requestOTP() }
        await returned.close() // Idempotent.

        escaped = nil
        await #expect(throws: Failure.self) {
            try await AnisetteContext.with(identifier: UUID(), configuration: configuration) { context in
                escaped = context
                throw Failure()
            }
        }
        let thrown = try #require(escaped)
        await #expect(throws: CancellationError.self) { try await thrown.requestOTP() }
    }

    @Test(.enabled(if: environment["ANISETTE_APPLE_DIR"] != nil))
    func prepareLoadsAndCachesRuntime() async throws {
        try await AnisetteContext.prepare(configuration: Self.cachedRuntime)
        try await AnisetteContext.prepare(configuration: Self.cachedRuntime)
    }

    @Test(.enabled(if: environment["ANISETTE_APPLE_DIR"] != nil))
    func scopedProvisioningPropagatesChallengeAndExchangeErrors() async throws {
        struct ExchangeFailure: Error {}

        var exchangeCalled = false
        let adiError = await #expect(throws: AnisetteError.self) {
            try await AnisetteContext.provision(
                identifier: UUID(),
                challenge: Data(count: 256),
                configuration: Self.cachedRuntime
            ) { _ in
                exchangeCalled = true
                return (Data(), Data())
            }
        }
        #expect(adiError?.adiStatus == -45031)
        #expect(!exchangeCalled)

        let invalidError = await #expect(throws: AnisetteError.self) {
            try await AnisetteContext.provision(
                identifier: UUID(),
                challenge: Data(),
                configuration: Self.cachedRuntime
            ) { _ in
                exchangeCalled = true
                return (Data(), Data())
            }
        }
        #expect(invalidError != nil && invalidError?.adiStatus == nil)
        #expect(!exchangeCalled)

        var escaped: AnisetteContext?
        var receivedChallenge: Data?
        await #expect(throws: ExchangeFailure.self) {
            try await AnisetteContext.provision(
                identifier: UUID(),
                configuration: Self.cachedRuntime,
                start: { context in
                    escaped = context
                    return AnisetteContext.ProvisioningSession(clientChallenge: Data("cpim".utf8), context: context)
                },
                exchange: { clientChallenge in
                    receivedChallenge = clientChallenge
                    throw ExchangeFailure()
                }
            )
        }
        #expect(receivedChallenge == Data("cpim".utf8))
        let context = try #require(escaped)
        #expect(await context.isClosed())
        await #expect(throws: CancellationError.self) { try await context.requestOTP() }
    }

    @Test(.enabled(if: environment["ANISETTE_APPLE_DIR"] != nil))
    func cancellingTaskClosesContext() async throws {
        let context = try await AnisetteContext.open(identifier: UUID(), configuration: Self.cachedRuntime)
        #expect(await !context.isClosed())
        let task = Task {
            await Task.yield()
            return try await context.requestOTP()
        }
        task.cancel()
        await #expect(throws: CancellationError.self) { try await task.value }
        #expect(await context.isClosed())
        await #expect(throws: CancellationError.self) { try await context.requestOTP() }
    }

    @Test(.enabled(if: environment["ANISETTE_APPLE_DIR"] != nil))
    func profileEntriesLieInTheirImages() throws {
        let profile = try Profile.load(assets: ProfileGeneration.localAssets())
        let expected = try PinnedBuild.current().preparedImageHashes
        for image in profile.images { #expect(Resources.hash(image.data) == expected[image.name]) }
        func contains(_ image: String, _ address: UInt64) throws -> Bool {
            let image = try #require(profile.images.first { $0.name == image })
            return image.segments.contains { $0.address <= address && address - $0.address < $0.size }
        }
        let entries = profile.entries
        for address in [entries.startProvisioning, entries.endProvisioning, entries.requestOTP] {
            #expect(try contains("commerce", address))
        }
        #expect(try contains("adid", entries.daemonMain))
        #expect(try contains("fairplayd", entries.fairPlayDaemonMain))
        for address in [entries.kernelStart, entries.kernelSetup, entries.kernelInit, entries.kernelMessage,
                        entries.kernelStackProbe, entries.kernelStackProbeValue] {
            #expect(try contains("FairPlayIOKit", address))
        }
    }

    /// An alias naming a case `dispatch` lacks would fail only when the guest first calls that import.
    /// Arguments are whatever the registers hold, so a handler may fail in other ways here.
    @Test(.enabled(if: environment["ANISETTE_APPLE_DIR"] != nil))
    func serviceAliasesNameImplementedHandlers() async throws {
        let resources = try await Resources.load(configuration: Self.cachedRuntime)
        let engine = try resources.engine.factory(cancellation: Cancellation())()
        let machine = try GuestMachine(name: "commerce", profile: resources.profile, engine: engine)
        func unsupported(_ handler: String) -> Bool {
            do { try machine.services.dispatch(handler) } catch {
                return "\(error)".hasPrefix("Guest called unsupported import")
            }
            return false
        }
        #expect(unsupported("notAGuestService"))
        for handler in Set(GuestServices.handlers.values).sorted() { #expect(!unsupported(handler), "\(handler)") }
    }

    @Test func pointerAuthenticationRewriting() {
        #expect(Profile.Image.withoutPointerAuthentication(0xd65f0bff) == 0xd65f03c0)
        #expect(Profile.Image.withoutPointerAuthentication(0xd503233f) == 0xd503201f)
        #expect(Profile.Image.withoutPointerAuthentication(0xd73f0820) == 0xd63f0020)
        #expect(Profile.Image.withoutPointerAuthentication(0xd65f03c0) == 0xd65f03c0)
    }

    @Test func ioAESKnownVector() throws {
        var key = Data(count: 40)
        try key.put(UInt32(0x89c), at: 36)
        let plaintext = Data(count: 16), iv = Data(count: 16)
        let (ciphertext, nextIV) = try GuestServices.ioAES(plaintext, iv: iv, operation: 0, keyData: key)
        #expect(ciphertext.map { String(format: "%02x", $0) }.joined() == "66e94bd4ef8a2c3b884cfa59ca342b2e")
        #expect(nextIV == ciphertext)
        let (decrypted, decryptIV) = try GuestServices.ioAES(ciphertext, iv: iv, operation: 1, keyData: key)
        #expect(decrypted == plaintext)
        #expect(decryptIV == ciphertext)
    }
}
#endif
