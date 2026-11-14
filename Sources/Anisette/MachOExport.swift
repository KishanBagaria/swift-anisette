import Foundation
import MachOKit

/// MachOKit's trie decoder uses pointer reads. Validate each node's complete
/// grammar first, including optional terminal fields and child strings.
enum MachOExport {
    static func read(_ data: Data, at offset: Int) throws -> ExportTrieEntry {
        var cursor = offset
        let length = try data.uleb(&cursor)
        try require(length <= UInt64(data.count - cursor), "Truncated export terminal")
        let end = cursor + Int(length)
        if length > 0 {
            let raw = try data.uleb(&cursor)
            try require(raw <= Int32.max, "Invalid export flags")
            let flags = ExportSymbolFlags(rawValue: Int32(raw))
            _ = try data.uleb(&cursor)
            if flags.contains(.reexport) { try skipString(data, cursor: &cursor, end: end) } else if
                flags.contains(.stub_and_resolver) || flags.contains(.function_variant) {
                _ = try data.uleb(&cursor)
            }
            try require(cursor <= end, "Export terminal exceeds node")
        }
        cursor = end
        let children = Int(try data.byte(&cursor))
        for _ in 0..<children {
            try skipString(data, cursor: &cursor, end: data.count)
            try require(try data.uleb(&cursor) < data.count, "Export child exceeds trie")
        }
        var next = offset
        let entry = data.withUnsafeBytes { bytes -> ExportTrieEntry? in
            guard let base = bytes.baseAddress else { return nil }
            return ExportTrieEntry.readNext(basePointer: base.assumingMemoryBound(to: UInt8.self),
                                            trieSize: bytes.count, nextOffset: &next)
        }
        guard let entry else { throw AnisetteError("Invalid Mach-O export node") }
        return entry
    }

    private static func skipString(_ data: Data, cursor: inout Int, end: Int) throws {
        try data.checkRange(cursor, end - cursor)
        guard let zero = data[cursor..<end].firstIndex(of: 0),
              String(bytes: data[cursor..<zero], encoding: .utf8) != nil else {
            throw AnisetteError("Invalid Mach-O export string")
        }
        cursor = zero + 1
    }
}

extension Data {
    /// Copies a fixed MachOKit layout without assuming alignment of the source.
    func machLayout<T: BitwiseCopyable>(at offset: Int, as type: T.Type = T.self) throws -> T {
        try checkRange(offset, MemoryLayout<T>.size)
        return withUnsafeBytes { $0.loadUnaligned(fromByteOffset: offset, as: T.self) }
    }

    /// Imported C unions and bitfields lack BitwiseCopyable conformance. Copy
    /// their representation into a caller-initialized C layout instead.
    func machLayout<T>(at offset: Int, into initial: T) throws -> T {
        let size = MemoryLayout<T>.size
        try checkRange(offset, size)
        var value = initial
        Swift.withUnsafeMutableBytes(of: &value) { destination in
            withUnsafeBytes { source in
                destination.copyMemory(from: UnsafeRawBufferPointer(rebasing: source[offset..<offset + size]))
            }
        }
        return value
    }
}
