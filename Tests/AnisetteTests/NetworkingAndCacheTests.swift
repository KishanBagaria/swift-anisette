#if os(macOS) || os(Linux)
import Crypto
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import Testing
@testable import Anisette

struct NetworkingAndCacheTests {
    // MARK: - HTTPClient Validation, Redirects & Retry

    @Test func httpResponseValidationChecksHTTPSStatusRangeAndLength() throws {
        let httpsURL = try #require(URL(string: "https://updates.cdn-apple.com/restore.ipsw"))
        let httpURL = try #require(URL(string: "http://updates.cdn-apple.com/restore.ipsw"))

        func makeHTTP(_ url: URL, status: Int, headers: [String: String] = [:]) throws -> HTTPURLResponse {
            try #require(HTTPURLResponse(url: url, statusCode: status, httpVersion: "HTTP/1.1", headerFields: headers))
        }

        // Non-HTTPS and non-HTTPURLResponse rejected.
        let nonHTTP = URLResponse(url: httpsURL, mimeType: nil, expectedContentLength: 10, textEncodingName: nil)
        #expect(throws: AnisetteError.self) {
            try AnisetteHTTPClient.validateResponse(nonHTTP, for: httpsURL, range: nil, limit: 1024).get()
        }
        #expect(throws: AnisetteError.self) {
            try AnisetteHTTPClient.validateResponse(makeHTTP(httpURL, status: 200), for: httpsURL, range: nil, limit: 1024).get()
        }

        // Full downloads require 200 and Content-Length <= limit.
        try AnisetteHTTPClient.validateResponse(
            makeHTTP(httpsURL, status: 200, headers: ["Content-Length": "100"]),
            for: httpsURL, range: nil, limit: 1024
        ).get()
        #expect(throws: AnisetteError.self) {
            try AnisetteHTTPClient.validateResponse(makeHTTP(httpsURL, status: 206), for: httpsURL, range: nil, limit: 1024).get()
        }
        #expect(throws: AnisetteError.self) {
            try AnisetteHTTPClient.validateResponse(makeHTTP(httpsURL, status: 404), for: httpsURL, range: nil, limit: 1024).get()
        }
        #expect(throws: AnisetteError.self) {
            try AnisetteHTTPClient.validateResponse(
                makeHTTP(httpsURL, status: 200, headers: ["Content-Length": "2048"]),
                for: httpsURL, range: nil, limit: 1024
            ).get()
        }

        // Ranged downloads require 206, matching Content-Range, and matching (or unknown) Content-Length.
        let range: Range<Int64> = 10..<20
        try AnisetteHTTPClient.validateResponse(
            makeHTTP(httpsURL, status: 206, headers: ["Content-Range": "bytes 10-19/1000", "Content-Length": "10"]),
            for: httpsURL, range: range, limit: 10
        ).get()
        try AnisetteHTTPClient.validateResponse(
            makeHTTP(httpsURL, status: 206, headers: ["Content-Range": "bytes 10-19/1000"]),
            for: httpsURL, range: range, limit: 10
        ).get()
        #expect(throws: AnisetteError.self) {
            try AnisetteHTTPClient.validateResponse(makeHTTP(httpsURL, status: 200), for: httpsURL, range: range, limit: 10).get()
        }
        #expect(throws: AnisetteError.self) {
            try AnisetteHTTPClient.validateResponse(makeHTTP(httpsURL, status: 206), for: httpsURL, range: range, limit: 10).get()
        }
        #expect(throws: AnisetteError.self) {
            try AnisetteHTTPClient.validateResponse(
                makeHTTP(httpsURL, status: 206, headers: ["Content-Range": "bytes 0-9/1000", "Content-Length": "10"]),
                for: httpsURL, range: range, limit: 10
            ).get()
        }
        #expect(throws: AnisetteError.self) {
            try AnisetteHTTPClient.validateResponse(
                makeHTTP(httpsURL, status: 206, headers: ["Content-Range": "bytes 10-19/1000", "Content-Length": "11"]),
                for: httpsURL, range: range, limit: 10
            ).get()
        }
    }

    @Test func httpBodyBufferEnforcesStreamingLimit() throws {
        let url = try #require(URL(string: "https://example.com/file.bin"))
        var buffer = AnisetteHTTPClient.BodyBuffer(limit: 8)
        try buffer.append(Data([1, 2, 3, 4]), for: url).get()
        try buffer.append(Data([5, 6, 7, 8]), for: url).get()
        #expect(buffer.data == Data([1, 2, 3, 4, 5, 6, 7, 8]))
        #expect(throws: AnisetteError.self) {
            try buffer.append(Data([9]), for: url).get()
        }
    }

    @Test func httpRedirectGuardsSchemeAndPreservesRangeHeader() throws {
        let origin = try #require(URL(string: "https://updates.cdn-apple.com/restore.ipsw"))
        let insecure = URLRequest(url: try #require(URL(string: "http://mirror.example.com/restore.ipsw")))
        #expect(throws: AnisetteError.self) {
            try AnisetteHTTPClient.validateRedirect(insecure, for: origin, range: 100..<200).get()
        }

        let secure = URLRequest(url: try #require(URL(string: "https://mirror.cdn-apple.com/restore.ipsw")))
        let allowed = try AnisetteHTTPClient.validateRedirect(secure, for: origin, range: 100..<200).get()
        #expect(allowed.value(forHTTPHeaderField: "Range") == "bytes=100-199")
        #expect(allowed.value(forHTTPHeaderField: "Accept-Encoding") == "identity")

        let fullAllowed = try AnisetteHTTPClient.validateRedirect(secure, for: origin, range: nil).get()
        #expect(fullAllowed.value(forHTTPHeaderField: "Range") == nil)
    }

    @Test func httpRetryPolicyRetriesOnlyTransientFailures() async throws {
        let url = try #require(URL(string: "https://example.com/asset.bin"))

        // Retries transient URLError and succeeds on the third attempt.
        let transientCount = Counter()
        let recovered = try await AnisetteHTTPClient.performWithRetry(for: url, backoff: [.zero, .zero]) {
            let attempt = await transientCount.increment()
            if attempt < 3 { throw URLError(.timedOut) }
            return Data("ok".utf8)
        }
        #expect(recovered == Data("ok".utf8))
        #expect(await transientCount.value == 3)

        // Retries RetryableError (e.g. HTTP 503) and succeeds on second attempt.
        let statusCount = Counter()
        let statusRecovered = try await AnisetteHTTPClient.performWithRetry(for: url, backoff: [.zero, .zero]) {
            if await statusCount.increment() == 1 {
                throw AnisetteHTTPClient.RetryableError(underlying: AnisetteError("HTTP 503"))
            }
            return Data("recovered".utf8)
        }
        #expect(statusRecovered == Data("recovered".utf8))
        #expect(await statusCount.value == 2)

        // Exhausting transient URLErrors wraps into AnisetteError.
        let exhaustedCount = Counter()
        await #expect(throws: AnisetteError.self) {
            _ = try await AnisetteHTTPClient.performWithRetry(for: url, backoff: [.zero, .zero]) {
                _ = await exhaustedCount.increment()
                throw URLError(.networkConnectionLost)
            }
        }
        #expect(await exhaustedCount.value == 3)

        // Non-retryable AnisetteError and CancellationError fail on the first attempt.
        let permanentCount = Counter()
        await #expect(throws: AnisetteError.self) {
            _ = try await AnisetteHTTPClient.performWithRetry(for: url, backoff: [.zero, .zero]) {
                _ = await permanentCount.increment()
                throw AnisetteError("HTTP 404")
            }
        }
        #expect(await permanentCount.value == 1)

        let cancelCount = Counter()
        await #expect(throws: CancellationError.self) {
            _ = try await AnisetteHTTPClient.performWithRetry(for: url, backoff: [.zero, .zero]) {
                _ = await cancelCount.increment()
                throw CancellationError()
            }
        }
        #expect(await cancelCount.value == 1)

        // Live client rejects non-HTTPS URLs upfront without touching the network.
        let httpURL = try #require(URL(string: "http://example.com/asset.bin"))
        await #expect(throws: AnisetteError.self) {
            _ = try await AnisetteHTTPClient.live.fetch(httpURL, nil)
        }
    }

    // MARK: - Synthetic AEA1 Round-Trip & Security Checks

    @Test func aeaRoundTripConcurrentReadAndIntegrityChecks() async throws {
        let segment0 = Data((0..<64).map { UInt8($0) })
        let segment1 = Data((0..<40).map { UInt8(255 - $0) })
        let expected = segment0 + segment1
        let fixture = try SyntheticAEA.build(segments: [segment0, segment1], segmentSize: 64)

        let keyFetches = Counter()
        let http = AnisetteHTTPClient { url, range in
            #expect(url.absoluteString == fixture.keyURL)
            #expect(range == nil)
            _ = await keyFetches.increment()
            return fixture.pem
        }

        let sourceReads = Counter()
        let archiveBytes = fixture.archive
        let trackedSource = AssetFile(size: UInt64(archiveBytes.count)) { offset, count in
            _ = await sourceReads.increment()
            await Task.yield()
            return try archiveBytes.bytes(at: Int(offset), size: count)
        }

        let aea = try await AEAFile.open(trackedSource, http: http)
        #expect(await keyFetches.value == 1)
        #expect(aea.size == UInt64(expected.count))
        #expect(aea.segments.count == 2)

        // Multi-segment read spanning both segments concurrently.
        let spanned = try await aea.file.read(50, 30)
        #expect(spanned == Data(expected[50..<80]))
        let full = try await aea.file.read(0, expected.count)
        #expect(full == expected)
        #expect(await sourceReads.value >= 2)

        // Coalescing: concurrent readers requesting the same uncached segment decode it once.
        let segReads = Counter()
        let freshSource = AssetFile(size: UInt64(archiveBytes.count)) { offset, count in
            if offset == aea.segments[0].offset {
                _ = await segReads.increment()
                try await Task.sleep(for: .milliseconds(25))
            }
            return try archiveBytes.bytes(at: Int(offset), size: count)
        }
        let freshAEA = try await AEAFile.open(freshSource, http: http)
        try await withThrowingTaskGroup(of: Data.self) { group in
            for _ in 0..<4 {
                group.addTask { try await freshAEA.file.read(0, 64) }
            }
            for try await chunk in group { #expect(chunk == segment0) }
        }
        #expect(await segReads.value == 1)

        // MAC failure: corrupting ciphertext in segment 1 is rejected.
        var badMAC = fixture.archive
        badMAC[badMAC.count - 1] ^= 0xff
        let badMACAEA = try await AEAFile.open(.memory(badMAC), http: http)
        await #expect(throws: AnisetteError.self) { _ = try await badMACAEA.file.read(64, 10) }

        // SHA-256 checksum failure: valid MACs with a mismatched segment checksum are rejected.
        let badChecksum = try SyntheticAEA.build(segments: [segment0, segment1], segmentSize: 64, corruptSegment1Checksum: true)
        let badChecksumHTTP = AnisetteHTTPClient { _, _ in badChecksum.pem }
        let badChecksumAEA = try await AEAFile.open(.memory(badChecksum.archive), http: badChecksumHTTP)
        await #expect(throws: AnisetteError.self) { _ = try await badChecksumAEA.file.read(64, 10) }
    }

    @Test(arguments: [
        "http://wkms-public.apple.com/keys/test",
        "https://evil.example.com/keys/test",
        "https://wkms-public.apple.com:8443/keys/test",
        "https://user@wkms-public.apple.com/keys/test",
        "https://user:pass@wkms-public.apple.com/keys/test",
    ])
    func aeaRejectsInvalidFCSKeyURLs(badURL: String) async throws {
        let fixture = try SyntheticAEA.build(segments: [Data(repeating: 7, count: 16)], segmentSize: 16, keyURL: badURL)
        let calls = Counter()
        let http = AnisetteHTTPClient { _, _ in
            _ = await calls.increment()
            return fixture.pem
        }
        await #expect(throws: AnisetteError.self) {
            _ = try await AEAFile.open(.memory(fixture.archive), http: http)
        }
        #expect(await calls.value == 0)
    }

    // MARK: - Coalescer Cooperative Cancellation & Deduplication

    @Test func resourceCacheDeduplicatesConcurrentLoadsAndCachesSuccess() async throws {
        let cache = Coalescer<String, String>()
        let key = "key"
        let invocations = Counter()
        let results = try await withThrowingTaskGroup(of: String.self) { group in
            for _ in 0..<5 {
                group.addTask {
                    try await cache.load(key) {
                        _ = await invocations.increment()
                        try await Task.sleep(for: .milliseconds(30))
                        return "loaded-value"
                    }
                }
            }
            var values: [String] = []
            for try await value in group { values.append(value) }
            return values
        }
        #expect(results == Array(repeating: "loaded-value", count: 5))
        #expect(await invocations.value == 1)

        let cached = try await cache.load(key) {
            _ = await invocations.increment()
            return "should-not-run"
        }
        #expect(cached == "loaded-value")
        #expect(await invocations.value == 1)
    }

    @Test func resourceCacheCancellingOneWaiterDoesNotCancelSiblingOrLoader() async throws {
        let cache = Coalescer<String, String>()
        let key = "key"
        let started = Signal()
        let release = Signal()
        let loaderCancelled = Signal()

        let waiter1 = Task {
            try await cache.load(key) {
                await withTaskCancellationHandler {
                    await started.fire()
                    await release.wait()
                    return "shared-result"
                } onCancel: {
                    Task { await loaderCancelled.fire() }
                }
            }
        }
        await started.wait()

        let waiter2 = Task {
            try await cache.load(key) { "unexpected-second-loader" }
        }
        // Let waiter2 attach to the in-flight entry before cancelling waiter1.
        try await Task.sleep(for: .milliseconds(20))

        waiter1.cancel()
        await #expect(throws: CancellationError.self) { _ = try await waiter1.value }
        #expect(!(await loaderCancelled.isFired))

        await release.fire()
        #expect(try await waiter2.value == "shared-result")
        #expect(!(await loaderCancelled.isFired))
    }

    @Test func resourceCacheCancellingAllWaitersCancelsUnderlyingLoader() async throws {
        let cache = Coalescer<String, String>()
        let key = "key"
        let started = Signal()
        let loaderCancelled = Signal()
        let runs = Counter()

        let waiter1 = Task {
            try await cache.load(key) {
                _ = await runs.increment()
                await started.fire()
                return try await withTaskCancellationHandler {
                    try await Task.sleep(for: .seconds(30))
                    return "never"
                } onCancel: {
                    Task { await loaderCancelled.fire() }
                }
            }
        }
        await started.wait()

        let waiter2 = Task {
            try await cache.load(key) { "unexpected" }
        }
        try await Task.sleep(for: .milliseconds(20))

        waiter1.cancel()
        await #expect(throws: CancellationError.self) { _ = try await waiter1.value }
        #expect(!(await loaderCancelled.isFired))

        waiter2.cancel()
        await #expect(throws: CancellationError.self) { _ = try await waiter2.value }
        await loaderCancelled.wait()
        #expect(await runs.value == 1)

        // Cache was cleared after cancellation, so a new caller succeeds.
        let retry = try await cache.load(key) {
            _ = await runs.increment()
            return "after-cancel"
        }
        #expect(retry == "after-cancel")
        #expect(await runs.value == 2)
    }

    @Test func resourceCacheClearsFailedEntrySoNextCallRetries() async throws {
        let cache = Coalescer<String, Int>()
        let key = "key"
        let attempts = Counter()
        await #expect(throws: AnisetteError.self) {
            _ = try await cache.load(key) {
                _ = await attempts.increment()
                throw AnisetteError("transient failure")
            }
        }
        let value = try await cache.load(key) {
            await attempts.increment()
        }
        #expect(value == 2)
        #expect(await attempts.value == 2)
    }

    // MARK: - Atomic 0600 Write & Multi-Version Cache Pruning

    @Test func writePrivateEnforcesAtomic0600FileAnd0700Directory() throws {
        let manager = FileManager.default
        let root = manager.temporaryDirectory.appendingPathComponent("anisette-private-\(UUID().uuidString)")
        defer { try? manager.removeItem(at: root) }
        try manager.createDirectory(at: root, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o755])

        let target = root.appendingPathComponent("secret.bin")
        let first = Data("initial private payload".utf8)
        try Resources.writePrivate(first, to: target)

        func posixMode(at path: String) throws -> Int {
            let value = try manager.attributesOfItem(atPath: path)[.posixPermissions]
            return try #require((value as? NSNumber)?.intValue ?? (value as? Int)) & 0o777
        }

        #expect(try Data(contentsOf: target) == first)
        #expect(try posixMode(at: root.path) == 0o700)
        #expect(try posixMode(at: target.path) == 0o600)

        // Overwrite atomically and confirm no temporary files remain.
        let updated = Data("replaced private payload".utf8)
        try Resources.writePrivate(updated, to: target)
        #expect(try Data(contentsOf: target) == updated)
        #expect(try posixMode(at: target.path) == 0o600)
        #expect(try manager.contentsOfDirectory(atPath: root.path) == ["secret.bin"])
    }

    @Test func cachePruningKeepsActiveRecentAndSecondMostRecentBuilds() throws {
        let manager = FileManager.default
        let root = manager.temporaryDirectory.appendingPathComponent("anisette-prune-\(UUID().uuidString)")
        defer { try? manager.removeItem(at: root) }
        try manager.createDirectory(at: root, withIntermediateDirectories: true)

        let now = Date()
        let day: TimeInterval = 24 * 60 * 60

        func makeDir(_ relativePath: String, lastUsedAgeDays: Double?, dirMtimeAgeDays: Double? = nil) throws -> URL {
            let dir = root.appendingPathComponent(relativePath)
            try manager.createDirectory(at: dir, withIntermediateDirectories: true)
            try Data("marker".utf8).write(to: dir.appendingPathComponent("payload.bin"))
            if let age = lastUsedAgeDays {
                Resources.touchLastUsed(in: dir, now: now.addingTimeInterval(-age * day))
            }
            if let mtimeAge = dirMtimeAgeDays {
                try manager.setAttributes([.modificationDate: now.addingTimeInterval(-mtimeAge * day)], ofItemAtPath: dir.path)
            }
            return dir
        }

        // Active + 2nd-most-recent old sibling kept; 3rd+ stale siblings deleted; unrelated dir untouched.
        let active = try makeDir("apple-assets-active", lastUsedAgeDays: 0)
        let secondOld = try makeDir("apple-assets-old-1", lastUsedAgeDays: 20)
        let thirdStale = try makeDir("apple-assets-old-2", lastUsedAgeDays: 30)
        let legacyStale = try makeDir("apple-assets-legacy", lastUsedAgeDays: nil, dirMtimeAgeDays: 40)
        let unrelated = try makeDir("custom-user-folder", lastUsedAgeDays: nil, dirMtimeAgeDays: 40)

        // Unicorn versions: active + 2nd-most-recent old version kept; 3rd stale version and its empty parent removed.
        let activeUnicornDir = try makeDir("unicorn/2.1.4/hash-active", lastUsedAgeDays: 0)
        let prevUnicornDir = try makeDir("unicorn/2.1.3/hash-prev", lastUsedAgeDays: 20)
        let staleUnicornDir = try makeDir("unicorn/2.0.0/hash-stale", lastUsedAgeDays: 30)

        Resources.pruneCache(
            in: root,
            keepingAssetFolder: "apple-assets-active",
            keepingUnicornPath: "unicorn/2.1.4/hash-active/libunicorn.2.dylib",
            maxAge: 14 * day,
            keepRecent: 2,
            now: now
        )

        #expect(manager.fileExists(atPath: active.path))
        #expect(manager.fileExists(atPath: secondOld.path))
        #expect(!manager.fileExists(atPath: thirdStale.path))
        #expect(!manager.fileExists(atPath: legacyStale.path))
        #expect(manager.fileExists(atPath: unrelated.path))

        #expect(manager.fileExists(atPath: activeUnicornDir.path))
        #expect(manager.fileExists(atPath: prevUnicornDir.path))
        #expect(!manager.fileExists(atPath: staleUnicornDir.path))
        #expect(!manager.fileExists(atPath: root.appendingPathComponent("unicorn/2.0.0").path))

        // Recent siblings (< 14 days) are also kept even beyond keepRecent = 2.
        let recent1 = try makeDir("apple-assets-recent-1", lastUsedAgeDays: 3)
        let recent2 = try makeDir("apple-assets-recent-2", lastUsedAgeDays: 10)
        Resources.pruneCache(
            in: root,
            keepingAssetFolder: "apple-assets-active",
            keepingUnicornPath: nil,
            maxAge: 14 * day,
            keepRecent: 2,
            now: now
        )
        #expect(manager.fileExists(atPath: active.path))
        #expect(manager.fileExists(atPath: recent1.path))
        #expect(manager.fileExists(atPath: recent2.path))
        #expect(!manager.fileExists(atPath: secondOld.path))
        #expect(manager.fileExists(atPath: unrelated.path))
    }
}

// MARK: - Test Helpers

private actor Counter {
    private(set) var value = 0
    func increment() -> Int {
        value += 1
        return value
    }
}

private actor Signal {
    private(set) var isFired = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func fire() {
        guard !isFired else { return }
        isFired = true
        let pending = waiters
        waiters.removeAll()
        for continuation in pending { continuation.resume() }
    }

    func wait() async {
        if isFired { return }
        await withCheckedContinuation { continuation in
            if isFired {
                continuation.resume()
            } else {
                waiters.append(continuation)
            }
        }
    }
}

private enum SyntheticAEA {
    struct Fixture {
        let archive: Data
        let pem: Data
        let keyURL: String
    }

    static func build(
        segments: [Data],
        segmentSize: Int,
        keyURL: String = "https://wkms-public.apple.com/keys/test",
        corruptSegment1Checksum: Bool = false
    ) throws -> Fixture {
        let privateKey = P256.KeyAgreement.PrivateKey()
        let pem = Data(privateKey.pemRepresentation.utf8)
        let symmetricKey = Data((0..<32).map { UInt8($0 ^ 0x5a) })
        var sender = try HPKE.Sender(
            recipientKey: privateKey.publicKey,
            ciphersuite: .P256_SHA256_AES_GCM_256,
            info: Data()
        )
        let wrapped = try sender.seal(symmetricKey)
        let fcsResponse = try JSONEncoder().encode([
            "enc-request": sender.encapsulatedKey.base64EncodedString(),
            "wrapped-key": wrapped.base64EncodedString(),
        ])
        let auth = metadataRecord("com.apple.wkms.fcs-key-url", Data(keyURL.utf8))
            + metadataRecord("com.apple.wkms.fcs-response", fcsResponse)
        let profile: UInt32 = 1
        let header = Data("AEA1".utf8) + Data.littleEndian(profile) + Data.littleEndian(UInt32(auth.count))
        let salt = Data(repeating: 0x11, count: 32)
        let mainKey = AEAFile.derive(symmetricKey, salt: salt, info: Data("AEA_AMK".utf8) + .littleEndian(profile), size: 32)

        let clusterCount = segments.count
        let clusterKey = AEAFile.derive(mainKey, info: Data("AEA_CK".utf8) + .littleEndian(UInt32(0)), size: 32)
        let clusterHeaderKey = AEAFile.derive(clusterKey, info: Data("AEA_CHEK".utf8), size: 80)

        var plainEntries = Data()
        var segmentMACs = Data()
        var segmentBodies = Data()
        for (index, plaintext) in segments.enumerated() {
            let segmentKey = AEAFile.derive(clusterKey, info: Data("AEA_SK".utf8) + .littleEndian(UInt32(index)), size: 80)
            let ciphertext = try AEAFile.decrypt(plaintext, key: segmentKey)
            var checksum = Data(SHA256.hash(data: plaintext))
            if corruptSegment1Checksum && index == 1 { checksum[0] ^= 0xff }
            plainEntries += Data.littleEndian(UInt32(plaintext.count))
                + Data.littleEndian(UInt32(ciphertext.count))
                + checksum
            segmentMACs += mac(segmentKey, data: ciphertext)
            segmentBodies += ciphertext
        }

        let encryptedEntries = try AEAFile.decrypt(plainEntries, key: clusterHeaderKey)
        let nextMAC = Data(count: 32)
        let clusterHeader = encryptedEntries + nextMAC + segmentMACs
        let clusterMAC = mac(clusterHeaderKey, data: encryptedEntries, salt: nextMAC + segmentMACs)

        let totalPlainSize = segments.reduce(0) { $0 + $1.count }
        let archiveSize = header.count + auth.count + salt.count + 112 + clusterHeader.count + segmentBodies.count
        var rootPlain = Data(count: 48)
        try rootPlain.put(UInt64(totalPlainSize), at: 0)
        try rootPlain.put(UInt64(archiveSize), at: 8)
        try rootPlain.put(UInt32(segmentSize), at: 16)
        try rootPlain.put(UInt32(clusterCount), at: 20)
        rootPlain[24] = 0x65
        rootPlain[25] = 2

        let rootKey = AEAFile.derive(mainKey, info: Data("AEA_RHEK".utf8), size: 80)
        let encryptedRoot = try AEAFile.decrypt(rootPlain, key: rootKey)
        let rootMAC = mac(rootKey, data: encryptedRoot, salt: clusterMAC + auth)
        let rootBlock = rootMAC + encryptedRoot + clusterMAC

        let archive = header + auth + salt + rootBlock + clusterHeader + segmentBodies
        return Fixture(archive: archive, pem: pem, keyURL: keyURL)
    }

    private static func metadataRecord(_ key: String, _ value: Data) -> Data {
        let body = Data(key.utf8) + Data([0]) + value
        return Data.littleEndian(UInt32(4 + body.count)) + body
    }

    private static func mac(_ key: Data, data: Data, salt: Data = Data()) -> Data {
        let message = salt + data + Data.littleEndian(UInt64(salt.count))
        return Data(HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key.prefix(32))))
    }
}
#endif
