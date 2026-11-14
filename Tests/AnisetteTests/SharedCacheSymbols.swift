#if os(macOS) || os(Linux)
import Foundation
import MachOKit
@testable import Anisette

/// Binds AppleMediaServices' imports against the pinned dyld shared cache the way dyld does:
/// by library ordinal, through re-exported dylibs and re-exported names. Only image headers,
/// export tries and a few pointer slots are read, never whole images.
final class SharedCacheSymbols {
    private enum Export { case address(UInt64), reexport(ordinal: Int, name: String) }
    private struct Image { let dependencies: [String]; let reexported: [String]; let exports: [String: Export] }
    private let cache = DyldAsset()
    private var paths: [String: UInt64] = [:]
    private var images: [String: Image] = [:]
    private var slideAdds: [UInt64: UInt64] = [:]

    init(_ tree: APFSTree) async throws {
        let (primary, header) = try await cache.open(tree)
        let offset = UInt64(try header.integer(at: 448, as: UInt32.self))
        let count = Int(try header.integer(at: 452, as: UInt32.self))
        try require(count > 0 && count <= 100000, "Invalid dyld image table")
        let table = try await primary.read(offset, count * 32)
        let entries = try (0..<count).map { index in
            (address: try table.integer(at: index * 32, as: UInt64.self),
             path: UInt64(try table.integer(at: index * 32 + 24, as: UInt32.self)))
        }
        // The cache builder packs image paths together, so one read covers them.
        guard let first = entries.map(\.path).min(), let last = entries.map(\.path).max(), last < primary.size else {
            throw AnisetteError("Invalid dyld image paths")
        }
        let end = min(primary.size, last + 4096)
        try require(end - first <= 16 << 20, "Dyld image paths exceed limit")
        let strings = try await primary.read(first, Int(end - first))
        for entry in entries { paths[try strings.cString(at: Int(entry.path - first), end: strings.count)] = entry.address }
    }

    /// The cache address dyld binds `name` to when `image` imports it from `path`.
    func address(of name: String, in path: String, depth: Int = 0) async throws -> UInt64? {
        try require(depth < 16, "Re-export chain too deep resolving \(name)")
        let image = try await image(path)
        switch image.exports[name] {
        case .address(let value): return value
        case let .reexport(ordinal, imported):
            try require(image.dependencies.indices.contains(ordinal - 1), "Invalid re-export ordinal for \(name)")
            return try await address(of: imported.isEmpty ? name : imported, in: image.dependencies[ordinal - 1], depth: depth + 1)
        case nil:
            for dependency in image.reexported {
                if let value = try await address(of: name, in: dependency, depth: depth + 1) { return value }
            }
            return nil
        }
    }

    /// The slid pointer stored at a cache address, or nil if the mapping holds no pointers.
    func pointer(at address: UInt64) async throws -> UInt64? {
        let mapping = try cache.mapping(address)
        guard mapping.slideSize > 0 else { return nil }
        try require(address - mapping.address <= mapping.size - 8, "Pointer exceeds dyld mapping")
        let valueAdd: UInt64
        if let known = slideAdds[mapping.address] { valueAdd = known } else {
            let header = try await mapping.file.read(mapping.slideOffset, 24)
            try require(try header.integer(at: 0, as: UInt32.self) == 5, "Unsupported dyld slide version")
            valueAdd = try header.integer(at: 16)
            slideAdds[mapping.address] = valueAdd
        }
        let raw: UInt64 = try await mapping.file.read(mapping.offset + address - mapping.address, 8).integer(at: 0)
        if raw == 0 { return 0 }
        guard let rebase = DyldChainedFixupPointerInfo(rawValue: raw, pointerFormat: .arm64e_shared_cache)?.rebase else {
            throw AnisetteError("Invalid shared-cache pointer")
        }
        return try guestAddress(valueAdd, offset: rebase.unpackedTarget)
    }

    private func image(_ path: String) async throws -> Image {
        if let image = images[path] { return image }
        guard let address = paths[path] else { throw AnisetteError("\(path) missing from dyld cache") }
        let mapping = try cache.mapping(address)
        let offset = mapping.offset + address - mapping.address
        let size = Int(try await mapping.file.read(offset, 32).integer(at: 20, as: UInt32.self))
        try require(size <= 4 << 20, "Dyld Mach-O load commands exceed limit")
        let header = try await mapping.file.read(offset, 32 + size)
        let macho = try MachO(header, validateFileRanges: false)
        let (dependencies, reexported) = try SharedCacheSymbols.dependencies(macho)
        var exports: [String: Export] = [:]
        if let linkedit = macho.segments.first(where: { $0.name == "__LINKEDIT" }) {
            let file = try cache.mapping(linkedit.address).file
            for command in macho.commands {
                let location: Int
                switch command.kind {
                case UInt32(LC_DYLD_EXPORTS_TRIE): location = command.offset + 8
                case UInt32(LC_DYLD_INFO), UInt32(LC_DYLD_INFO_ONLY): location = command.offset + 40
                default: continue
                }
                let length = Int(try header.integer(at: location + 4, as: UInt32.self))
                try require(length <= 16 << 20, "Dyld export table exceeds limit")
                if length > 0 {
                    let trie = try await file.read(UInt64(try header.integer(at: location, as: UInt32.self)), length)
                    exports = try Self.exports(trie, base: macho.base)
                }
            }
        }
        let image = Image(dependencies: dependencies, reexported: reexported, exports: exports)
        images[path] = image
        return image
    }

    /// Install names in library-ordinal order, and the subset this image re-exports.
    static func dependencies(_ image: MachO) throws -> ([String], [String]) {
        var all: [String] = [], reexported: [String] = []
        for command in image.commands where [UInt32(LC_LOAD_DYLIB), UInt32(LC_LOAD_WEAK_DYLIB), UInt32(LC_REEXPORT_DYLIB),
                                             UInt32(LC_LOAD_UPWARD_DYLIB), UInt32(LC_LAZY_LOAD_DYLIB)].contains(command.kind) {
            try require(command.size >= 24, "Truncated dylib command")
            let name = Int(try image.data.integer(at: command.offset + 8, as: UInt32.self))
            try require(name >= 24 && name < command.size, "Invalid dylib name")
            let path = try image.data.cString(at: command.offset + name, end: command.offset + command.size)
            all.append(path)
            if command.kind == UInt32(LC_REEXPORT_DYLIB) { reexported.append(path) }
        }
        return (all, reexported)
    }

    private static func exports(_ trie: Data, base: UInt64) throws -> [String: Export] {
        var result: [String: Export] = [:]
        var pending: [(Int, String, Set<Int>)] = [(0, "", [])], visited = 0
        while let (offset, prefix, ancestors) = pending.popLast() {
            try require(!ancestors.contains(offset) && prefix.utf8.count <= 4096 && visited < 1 << 20,
                        "Invalid Mach-O export trie")
            visited += 1
            let entry = try MachOExport.read(trie, at: offset)
            if let content = entry.content, let flags = content.flags {
                if flags.contains(.reexport) {
                    result[prefix] = .reexport(ordinal: Int(content.ordinal ?? 0), name: content.importedName ?? "")
                } else if let target = content.symbolOffset ?? content.stub {
                    let value = try flags.kind == .absolute ? UInt64(target) : guestAddress(base, offset: UInt64(target))
                    result[prefix] = .address(value)
                }
            }
            for child in entry.children {
                pending.append((Int(child.offset), prefix + child.label, ancestors.union([offset])))
            }
        }
        return result
    }
}
#endif
