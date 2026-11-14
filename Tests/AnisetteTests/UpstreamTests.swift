import Foundation
import Testing
@testable import Anisette

/// Checks that the pinned upstream downloads still exist, using the runtime's own
/// constants and HTTP client. Run weekly by .github/workflows/upstream-check.yml.
@Suite(.enabled(if: ProcessInfo.processInfo.environment["ANISETTE_TEST_UPSTREAM"] == "1"))
struct UpstreamTests {
    /// The last byte must exist (206 with a matching Content-Range), and the ZIP
    /// end record must sit exactly at the pinned size. Reads about 64 KB.
    @Test func pinnedRestoreImageIsAvailable() async throws {
        let build = try PinnedBuild.current(), size = build.restoreImageSize
        let last = try await AnisetteHTTPClient.live.fetch(build.restoreImageURL, Int64(size - 1)..<Int64(size))
        #expect(last.count == 1)
        let archive = try await RestoreArchive.open(RemoteAssetFile(http: .live, build: build).file)
        #expect(!archive.entries.isEmpty)
    }

    @Test(arguments: UnicornArtifact.all.map(\.url))
    func pinnedUnicornWheelIsAvailable(url: URL) async throws {
        let artifact = try #require(UnicornArtifact.all.first { $0.url == url })
        let archive = try await AnisetteHTTPClient.live.fetch(artifact.url, nil)
        #expect(Resources.hash(archive) == artifact.archiveHash)
        let library = try UnicornArtifact.member(artifact.member, in: archive)
        #expect(Resources.hash(library) == artifact.libraryHash)
    }
}
