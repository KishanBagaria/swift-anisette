import Foundation
import MachOKit

enum MachOExport {
    static func read(_ data: Data, at offset: Int) throws -> ExportTrieEntry {
        var next = offset
        let entry = data.withUnsafeBytes { bytes -> ExportTrieEntry? in
            guard let base = bytes.baseAddress else { return nil }
            return ExportTrieEntry.readNext(basePointer: base.assumingMemoryBound(to: UInt8.self),
                                            trieSize: bytes.count, nextOffset: &next)
        }
        guard let entry else { throw AnisetteError("Invalid Mach-O export node") }
        return entry
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
