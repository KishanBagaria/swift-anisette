// Adapted from go-apfs v1.0.29 (Copyright 2020-2026 blacktop), Apache-2.0.
// Modified for swift-anisette: Swift translation and a bounded, asynchronous read-only subset.
// See Resources/LICENSE.go-apfs and Resources/NOTICE.txt.

import Foundation
import MachOKit

enum APFSFile {
    struct Extent: Sendable { let logical: UInt64; let physical: UInt64; let length: UInt64 }

    // swiftlint:disable:next cyclomatic_complexity
    static func open(_ path: String, in tree: APFSTree) async throws -> AssetFile {
        let records = try await tree.resolve(path)
        guard let inode = try records.first(where: { try $0.kind == 3 })?.value else { throw AnisetteError("APFS file has no inode") }
        var compression: Data?, resource: Data?
        var extents: [Extent] = []
        for record in records {
            switch try record.kind {
            case 4:
                let length = Int(try record.key.integer(at: 8, as: UInt16.self))
                let name = String(decoding: try record.key.bytes(at: 10, size: length).prefix { $0 != 0 }, as: UTF8.self)
                let flags: UInt16 = try record.value.integer(at: 0)
                let size = Int(try record.value.integer(at: 2, as: UInt16.self))
                let data = try record.value.bytes(at: 4, size: size)
                if name == "com.apple.decmpfs" {
                    try require(flags & 2 != 0, "Compression metadata must be embedded")
                    compression = data
                } else if name == "com.apple.ResourceFork" {
                    try require(flags & 1 != 0, "Resource fork must be a data stream")
                    resource = data
                }
            case 8:
                extents.append(try .init(record))
            default: break
            }
        }
        if let compression {
            try require(try compression.integer(at: 0, as: UInt32.self) == 0x636d7066, "Invalid decmpfs metadata")
            guard let resource else { throw AnisetteError("Compressed APFS file has no resource fork") }
            let fork = try await extentFile(tree.source, extents: tree.dataExtents(resource.integer(at: 0)),
                                            size: resource.integer(at: 8))
            return try await DecmpfsFile.open(fork, size: compression.integer(at: 8), method: compression.integer(at: 4)).file
        }
        var size: UInt64 = try inode.integer(at: 84)
        if inode.count > 92 {
            let count = Int(try inode.integer(at: 92, as: UInt16.self))
            var position = 96 + count * 4
            try inode.checkRange(96, count * 4)
            for index in 0..<count {
                let length = Int(try inode.integer(at: 98 + index * 4, as: UInt16.self))
                try inode.checkRange(position, length)
                if inode[96 + index * 4] == 8 {
                    try require(length >= 40, "Truncated inode data stream")
                    size = try inode.integer(at: position)
                }
                position += (length + 7) & ~7
            }
        }
        if extents.isEmpty && size > 0 { extents = try await tree.dataExtents(inode.integer(at: 8)) }
        return try extentFile(tree.source, extents: extents, size: size)
    }

    static func extentFile(_ source: AssetFile, extents: [Extent], size: UInt64) throws -> AssetFile {
        let extents = extents.sorted { $0.logical < $1.logical }
        var position: UInt64 = 0
        for extent in extents {
            try require(extent.logical == position && extent.length > 0 && extent.physical <= source.size / 4096,
                        "Invalid or sparse APFS extent")
            let offset = extent.physical * 4096
            try require(extent.length <= source.size - offset, "APFS extent exceeds image")
            position = try guestAddress(position, offset: extent.length)
        }
        try require(size <= position, "APFS extents do not cover file")
        return AssetFile(size: size) { offset, count in
            var position = offset, result = Data()
            for extent in extents where result.count < count && position >= extent.logical
                && position - extent.logical < extent.length {
                let length = Int(min(UInt64(count - result.count), extent.length - (position - extent.logical)))
                result.append(try await source.read(extent.physical * 4096 + position - extent.logical, length))
                position += UInt64(length)
            }
            return result
        }
    }

    static func arm64e(_ file: AssetFile) async throws -> AssetFile {
        let bytes = try await file.read(0, MemoryLayout<fat_header>.size)
        var layout: fat_header = try bytes.machLayout(at: 0)
        if layout.magic != FAT_CIGAM { return file }
        layout.magic = layout.magic.byteSwapped; layout.nfat_arch = layout.nfat_arch.byteSwapped
        let header = FatHeader(layout: layout)
        let count = Int(layout.nfat_arch)
        try require(count > 0 && count <= 64, "Invalid universal binary architecture count")
        let table = try await file.read(8, count * MemoryLayout<fat_arch>.size)
        for arch in header.arches(data: table, isSwapped: true) {
            if arch.cpuSubType == .arm64(.arm64e) {
                try require(arch.offset >= 8 + UInt64(table.count) && arch.size > 0, "Invalid arm64e slice")
                return try file.section(arch.offset, arch.size)
            }
        }
        throw AnisetteError("Universal binary has no arm64e slice")
    }
}

final class DecmpfsFile: Sendable {
    private let source: AssetFile
    private let size: UInt64
    private let method: UInt32
    private let offsets: [UInt32]
    private let cache = AssetDataCache(maximum: 8 << 20)

    private init(source: AssetFile, size: UInt64, method: UInt32, offsets: [UInt32]) {
        self.source = source; self.size = size; self.method = method; self.offsets = offsets
    }

    static func open(_ source: AssetFile, size: UInt64, method: UInt32) async throws -> DecmpfsFile {
        try require([8, 12, 14].contains(method) && size > 0 && size <= 64 << 30, "Unsupported decmpfs encoding")
        let count = Int((size + 65535) / 65536)
        let table = try await source.read(0, (count + 1) * 4)
        let offsets = try (0...count).map { try table.integer(at: $0 * 4, as: UInt32.self) }
        try require(offsets[0] == table.count && UInt64(offsets[count]) == source.size, "Invalid decmpfs index")
        for index in 0..<count {
            try require(offsets[index + 1] > offsets[index] && offsets[index + 1] - offsets[index] <= 65537,
                        "Invalid decmpfs block range")
        }
        return DecmpfsFile(source: source, size: size, method: method, offsets: offsets)
    }

    var file: AssetFile {
        AssetFile(size: size) { offset, count in
            var position = offset, result = Data()
            while result.count < count {
                let bytes = try await self.block(Int(position / 65536))
                let inside = Int(position % 65536)
                let length = min(count - result.count, bytes.count - inside)
                try require(length > 0, "Incomplete decmpfs block")
                result.append(try bytes.bytes(at: inside, size: length)); position += UInt64(length)
            }
            return result
        }
    }

    private func block(_ index: Int) async throws -> Data {
        if let data = cache[UInt64(index)] { return data }
        let compressed = try await source.read(UInt64(offsets[index]), Int(offsets[index + 1] - offsets[index]))
        let expected = Int(min(65536, size - UInt64(index) * 65536))
        let data = try Self.decode(compressed, method: method, size: expected)
        cache[UInt64(index)] = data
        return data
    }

    static func decode(_ data: Data, method: UInt32, size: Int) throws -> Data {
        guard let first = data.first else { throw AnisetteError("Empty decmpfs block") }
        let decoded: Data
        switch method {
        case 8: decoded = try first == 6 ? Data(data.dropFirst()) : data.lzfseDecoded(size: size, lzvn: true)
        case 12: decoded = try first != 0x62 ? Data(data.dropFirst()) : data.lzfseDecoded(size: size)
        case 14: decoded = try first == 0xff ? Data(data.dropFirst()) : LZBitmap.decode(data, maximum: size)
        default: throw AnisetteError("Unsupported decmpfs method")
        }
        try require(decoded.count == size, "decmpfs block size mismatch")
        return decoded
    }
}

extension APFSFile.Extent {
    /// Decodes a file-extent record (`j_file_extent_key_t` / `j_file_extent_val_t`).
    init(_ record: APFSTree.Record) throws {
        try self.init(logical: record.key.integer(at: 8), physical: record.value.integer(at: 8),
                      length: record.value.integer(at: 0, as: UInt64.self) & 0x00ffffffffffffff)
    }
}
