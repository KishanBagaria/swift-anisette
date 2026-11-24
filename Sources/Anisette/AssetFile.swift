import Foundation

/// A bounded, random-access view. Views compose without downloading their parent.
struct AssetFile: Sendable {
    let size: UInt64
    let readBytes: @Sendable (UInt64, Int) async throws -> Data

    func read(_ offset: UInt64, _ count: Int) async throws -> Data {
        try Task.checkCancellation()
        try require(count >= 0 && count <= 256 << 20 && offset <= size && UInt64(count) <= size - offset,
                    "Asset read exceeds file bounds")
        if count == 0 { return Data() }
        let bytes = try await readBytes(offset, count)
        try require(bytes.count == count, "Truncated asset read")
        return bytes
    }

    func section(_ offset: UInt64, _ length: UInt64) throws -> Self {
        try require(offset <= size && length <= size - offset, "Asset section exceeds file bounds")
        return Self(size: length) { position, count in try await read(offset + position, count) }
    }

    static func memory(_ data: Data) -> Self {
        let bytes = Data(data)
        return Self(size: UInt64(bytes.count)) { offset, count in try bytes.bytes(at: Int(offset), size: count) }
    }
}

/// The restore image is immutable and pinned along with its archive size (see PinnedBuild). The
/// ZIP directory, AEA keys and segments, filesystem and cache layouts are read
/// from the image itself, never from a generated extraction plan.
final class RemoteAssetFile: Sendable {
    private let http: AnisetteHTTPClient
    private let url: URL
    private let size: UInt64
    private let cache = AssetDataCache(maximum: 8 << 20)

    init(http: AnisetteHTTPClient, url: URL, size: UInt64) { self.http = http; self.url = url; self.size = size }

    convenience init(http: AnisetteHTTPClient, build: PinnedBuild) {
        self.init(http: http, url: build.restoreImageURL, size: build.restoreImageSize)
    }

    var file: AssetFile {
        let url = url, size = size
        return AssetFile(size: size) { offset, count in
            // Small metadata reads share pages; large reads use exact ranges.
            if count > 32768 {
                return try await self.http.fetch(url, Int64(offset)..<Int64(offset + UInt64(count)))
            }
            let page = offset & ~UInt64(32767)
            let length = Int(min(size - page, 65536))
            let data: Data
            if let cached = self.cache[page] { data = cached } else {
                data = try await self.http.fetch(url, Int64(page)..<Int64(page + UInt64(length)))
                self.cache[page] = data
            }
            return try data.bytes(at: Int(offset - page), size: count)
        }
    }
}

/// Thread-safe bounded FIFO cache owned by each reader; no file or decrypted block cache
/// survives an installation.
final class AssetDataCache: @unchecked Sendable {
    private let lock = NSLock()
    private let maximum: Int
    private var bytes = 0
    private var values: [UInt64: Data] = [:]
    private var order: [UInt64] = []

    init(maximum: Int) { self.maximum = maximum }

    subscript(key: UInt64) -> Data? {
        get {
            lock.lock()
            defer { lock.unlock() }
            return values[key]
        }
        set {
            lock.lock()
            defer { lock.unlock() }
            guard let data = newValue, data.count <= maximum else { return }
            if let old = values.removeValue(forKey: key) {
                bytes -= old.count
                order.removeAll { $0 == key }
            }
            while bytes + data.count > maximum, let oldest = order.first {
                bytes -= values.removeValue(forKey: oldest)?.count ?? 0
                order.removeFirst()
            }
            values[key] = data
            order.append(key)
            bytes += data.count
        }
    }
}
