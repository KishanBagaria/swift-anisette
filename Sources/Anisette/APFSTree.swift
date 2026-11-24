// Adapted from go-apfs v1.0.29 (Copyright 2020-2026 blacktop), Apache-2.0.
// Modified for swift-anisette: Swift translation and a bounded, asynchronous read-only subset.
// See Resources/LICENSE.go-apfs and Resources/NOTICE.txt.

import Foundation
import Crypto

/// The read-only subset used by Apple's pinned restore volumes: physical object
/// maps, virtual and sealed filesystem trees, and physical extent trees.
/// Metadata fields are populated during `open(_:)` and immutable thereafter; `cache` is thread-safe.
final class APFSTree: @unchecked Sendable {
    struct Record: Sendable {
        let key: Data
        let value: Data
        var object: UInt64 { get throws { try key.integer(at: 0, as: UInt64.self) & 0x0fffffffffffffff } }
        var kind: UInt64 { get throws { try key.integer(at: 0, as: UInt64.self) >> 60 } }
    }
    struct Node: Sendable {
        let flags: UInt16
        let level: UInt16
        let records: [Record]
    }

    let source: AssetFile
    private let cache = AssetDataCache(maximum: 16 << 20)
    private var omap: UInt64 = 0
    private var transaction: UInt64 = 0
    private var rootOID: UInt64 = 0
    private var root: UInt64 = 0
    private var extentRoot: UInt64 = 0

    private init(source: AssetFile) { self.source = source }

    static func open(_ source: AssetFile) async throws -> APFSTree {
        let tree = APFSTree(source: source)
        var container = try await tree.block(0)
        try require(try container.integer(at: 32, as: UInt32.self) == 0x4253584e
            && container.integer(at: 36, as: UInt32.self) == 4096, "Unsupported APFS container")
        let count = Int(try container.integer(at: 104, as: UInt32.self))
        let base: UInt64 = try container.integer(at: 112)
        try require(count <= 4096 && base <= source.size / 4096 && UInt64(count) <= source.size / 4096 - base,
                    "Unsupported APFS checkpoint area")
        for index in 0..<count {
            // Checkpoint slots may be unused or from an incomplete transaction.
            let candidate = try await tree.source.read(guestAddress(base, offset: UInt64(index)) * 4096, 4096)
            if try candidate.integer(at: 32, as: UInt32.self) == 0x4253584e,
               checksum(candidate), try candidate.integer(at: 16, as: UInt64.self) > container.integer(at: 16, as: UInt64.self) {
                container = candidate
            }
        }
        let containerMap = try await tree.block(container.integer(at: 160))
        let containerRoot: UInt64 = try containerMap.integer(at: 48)
        let volumeOID: UInt64 = try container.integer(at: 184)
        try require(volumeOID != 0, "APFS container has no volume")
        let volumeAddress = try await tree.mapping(containerRoot, object: volumeOID,
                                                   transaction: container.integer(at: 16))
        let volume = try await tree.block(volumeAddress)
        try require(try volume.integer(at: 32, as: UInt32.self) == 0x42535041, "Invalid APFS volume")
        let volumeMap = try await tree.block(volume.integer(at: 128))
        tree.omap = try volumeMap.integer(at: 48)
        tree.transaction = try volumeMap.integer(at: 16)
        tree.rootOID = try volume.integer(at: 136)
        tree.extentRoot = try volume.integer(at: 1032)
        tree.root = try await tree.mapping(tree.omap, object: tree.rootOID, transaction: tree.transaction)
        return tree
    }

    func block(_ address: UInt64, hash: Data? = nil) async throws -> Data {
        try require(address < source.size / 4096, "APFS block exceeds image")
        let data: Data
        if let cached = cache[address] { data = cached } else {
            data = try await source.read(address * 4096, 4096)
            let sealed = try data.prefix(32).allSatisfy { $0 == 0 }
                && (try data.integer(at: 32, as: UInt16.self)) & 0x10 != 0
            try require(sealed || Self.checksum(data), "APFS block checksum mismatch")
            cache[address] = data
        }
        if let hash { try require(Data(SHA256.hash(data: data)) == hash, "APFS child hash mismatch") }
        return data
    }

    static func checksum(_ data: Data) -> Bool {
        guard data.count == 4096 else { return false }
        let modulus: UInt64 = 0xffffffff
        var sum: UInt64 = 0, sum2: UInt64 = 0
        for offset in stride(from: 8, to: data.count, by: 4) {
            let value = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset, as: UInt32.self) }
            sum = (sum + UInt64(UInt32(littleEndian: value))) % modulus
            sum2 = (sum2 + sum) % modulus
        }
        let first = modulus - (sum + sum2) % modulus
        let second = modulus - (sum + first) % modulus
        return (try? data.integer(at: 0, as: UInt64.self)) == first | second << 32
    }

    static func node(_ data: Data) throws -> Node {
        try require(data.count == 4096, "Invalid APFS tree block size")
        let flags: UInt16 = try data.integer(at: 32)
        let level: UInt16 = try data.integer(at: 34)
        let count = Int(try data.integer(at: 36, as: UInt32.self))
        let tableOffset = Int(try data.integer(at: 40, as: UInt16.self))
        let tableSize = Int(try data.integer(at: 42, as: UInt16.self))
        let fixed = flags & 4 != 0
        let stride = fixed ? 4 : 8
        let keyBase = 56 + tableSize
        let valueEnd = data.count - (flags & 1 == 0 ? 0 : 40)
        try require(level < 32 && count <= 1024 && tableOffset + count * stride <= tableSize
            && keyBase <= valueEnd, "Invalid APFS tree table")
        var records: [Record] = []
        for index in 0..<count {
            let location = 56 + tableOffset + index * stride
            let keyOffset = Int(try data.integer(at: location, as: UInt16.self))
            let keySize = fixed ? 16 : Int(try data.integer(at: location + 2, as: UInt16.self))
            let valueOffset = Int(try data.integer(at: location + (fixed ? 2 : 4), as: UInt16.self))
            let valueSize = fixed ? (level > 0 ? 8 : 16) : Int(try data.integer(at: location + 6, as: UInt16.self))
            try require(keyOffset + keySize <= valueEnd - keyBase && valueOffset <= valueEnd - keyBase
                && valueSize <= valueOffset && keySize >= 8, "Invalid APFS record bounds")
            records.append(.init(key: try data.bytes(at: keyBase + keyOffset, size: keySize),
                                 value: try data.bytes(at: valueEnd - valueOffset, size: valueSize)))
        }
        return Node(flags: flags, level: level, records: records)
    }

    private func mapping(_ root: UInt64, object: UInt64, transaction: UInt64) async throws -> UInt64 {
        var address = root, visited: Set<UInt64> = []
        for _ in 0..<32 {
            try require(visited.insert(address).inserted, "Cycle in APFS object map")
            let node = try Self.node(await block(address))
            var selected: Record?
            for record in node.records {
                let oid: UInt64 = try record.key.integer(at: 0), xid: UInt64 = try record.key.integer(at: 8)
                if oid < object || (oid == object && xid <= transaction) { selected = record } else { break }
            }
            guard let record = selected else { throw AnisetteError("Missing APFS object mapping") }
            if node.level == 0 {
                try require(try record.key.integer(at: 0, as: UInt64.self) == object
                    && record.value.integer(at: 0, as: UInt32.self) & 1 == 0, "Deleted or missing APFS object")
                return try record.value.integer(at: 8)
            }
            address = try record.value.integer(at: 0)
        }
        throw AnisetteError("APFS object-map depth exceeds limit")
    }

    func records(_ object: UInt64, extents: Bool = false) async throws -> [Record] {
        var visited: Set<UInt64> = []
        return try await collect(extents ? extentRoot : root, object: object, physical: extents, visited: &visited, depth: 0)
    }

    private func collect(_ address: UInt64, object: UInt64, physical: Bool,
                         visited: inout Set<UInt64>, depth: Int, hash: Data? = nil) async throws -> [Record] {
        try require(depth < 32 && visited.count < 4096 && visited.insert(address).inserted, "APFS tree cycle or limit exceeded")
        let node = try Self.node(await block(address, hash: hash))
        func oid(_ record: Record) throws -> UInt64 {
            try physical ? record.key.integer(at: 0) : record.object
        }
        if node.level == 0 { return try node.records.filter { try oid($0) == object } }
        var result: [Record] = []
        for (index, record) in node.records.enumerated() {
            let lower = try oid(record)
            let upper = try index + 1 < node.records.count ? oid(node.records[index + 1]) : UInt64.max
            if object < lower || object > upper { continue }
            var child: UInt64 = try record.value.integer(at: 0)
            var hash: Data?
            if !physical {
                if node.flags & 8 != 0 {
                    child = try guestAddress(rootOID, offset: child)
                    hash = try record.value.bytes(at: 8, size: 32)
                }
                child = try await mapping(omap, object: child, transaction: transaction)
            }
            result += try await collect(child, object: object, physical: physical,
                                        visited: &visited, depth: depth + 1, hash: hash)
        }
        return result
    }

    func resolve(_ path: String) async throws -> [Record] {
        var object: UInt64 = 2
        for component in path.split(separator: "/") {
            let records = try await records(object)
            var found: UInt64?
            for record in records where try record.kind == 9 {
                let length = Int(try record.key.integer(at: 8, as: UInt32.self) & 0x3ff)
                let name = try record.key.bytes(at: 12, size: length)
                if String(decoding: name.prefix { $0 != 0 }, as: UTF8.self) == component {
                    found = try record.value.integer(at: 0); break
                }
            }
            guard let next = found else { throw AnisetteError("APFS path component missing: \(component)") }
            object = next
        }
        return try await records(object)
    }

    func dataExtents(_ object: UInt64) async throws -> [APFSFile.Extent] {
        let physical = extentRoot != 0
        return try await records(object, extents: physical).compactMap { record in
            if try !physical && record.kind != 8 { return nil }
            return try APFSFile.Extent(record)
        }
    }
}
