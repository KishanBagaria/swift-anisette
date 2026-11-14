import Foundation
import MachOKit

/// Discovers shared-cache members, image segments, slide tables and symbols
/// from the downloaded cache headers. Only the selected image's pages are read.
final class DyldAsset {
    struct Mapping {
        let file: AssetFile
        let address: UInt64
        let size: UInt64
        let offset: UInt64
        let slideOffset: UInt64
        let slideSize: UInt64
    }
    static let path = "/System/Library/dyld/dyld_shared_cache_arm64e"
    static let image = "/System/Library/PrivateFrameworks/AppleMediaServices.framework/Versions/A/AppleMediaServices"
    private(set) var mappings: [Mapping] = []

    func extract(from tree: APFSTree) async throws -> Data {
        let (primary, header) = try await open(tree)
        let imageAddress = try await findImage(primary, header: header)
        let imageMapping = try mapping(imageAddress)
        let imageOffset = imageMapping.offset + imageAddress - imageMapping.address
        let first = try await imageMapping.file.read(imageOffset, 32)
        let commands = Int(try first.integer(at: 20, as: UInt32.self))
        try require(commands <= 4 << 20, "Dyld Mach-O load commands exceed limit")
        let imageHeader = try await imageMapping.file.read(imageOffset, 32 + commands)
        let image = try MachO(imageHeader, validateFileRanges: false)
        guard let linkedit = image.segments.first(where: { $0.name == "__LINKEDIT" }) else {
            throw AnisetteError("Shared-cache image has no linkedit segment")
        }
        let linkFile = try mapping(linkedit.address).file
        var segments: [MachOExtraction.Region] = [], slides: [MachOExtraction.Region] = []
        var slideAddresses: Set<UInt64> = []
        for segment in image.segments where segment.name != "__LINKEDIT" && segment.length > 0 {
            let mapping = try mapping(segment.address)
            let start = segment.address & ~UInt64(16383)
            let end = try guestAligned(guestAddress(segment.address, offset: UInt64(segment.length)), to: 16384)
            try require(start >= mapping.address && end - mapping.address <= mapping.size, "Dyld segment exceeds mapping")
            let data = try await mapping.file.read(mapping.offset + start - mapping.address, Int(end - start))
            segments.append(.init(address: start, data: data))
            if mapping.slideSize > 0 && slideAddresses.insert(mapping.address).inserted {
                try require(mapping.slideSize <= 16 << 20, "Dyld slide table exceeds limit")
                slides.append(.init(address: mapping.address,
                                    data: try await mapping.file.read(mapping.slideOffset, Int(mapping.slideSize))))
            }
        }
        let (symbols, strings) = try await symbols(image, file: linkFile)
        var exports = Data()
        for command in image.commands {
            let location: Int
            switch command.kind {
            case UInt32(LC_DYLD_EXPORTS_TRIE): location = command.offset + 8
            case UInt32(LC_DYLD_INFO), UInt32(LC_DYLD_INFO_ONLY): location = command.offset + 40
            default: continue
            }
            let offset = UInt64(try imageHeader.integer(at: location, as: UInt32.self))
            let length = Int(try imageHeader.integer(at: location + 4, as: UInt32.self))
            try require(length <= 16 << 20, "Dyld export table exceeds limit")
            if length > 0 { exports = try await linkFile.read(offset, length) }
        }
        return try MachOExtraction.dyld(header: imageHeader, segments: segments, exports: exports, slides: slides,
                                        symbols: symbols, strings: strings)
    }

    func open(_ tree: APFSTree) async throws -> (AssetFile, Data) {
        let primary = try await APFSFile.open(Self.path, in: tree)
        let header = try await add(primary)
        let offset = UInt64(try header.integer(at: 392, as: UInt32.self))
        let count = Int(try header.integer(at: 396, as: UInt32.self))
        try require(count <= 128, "Too many dyld subcaches")
        let entries = try await primary.read(offset, count * 56)
        for index in 0..<count {
            let item = index * 56
            let suffix = try entries.cString(at: item + 24, end: item + 56)
            try require(!suffix.isEmpty && !suffix.contains("/") && !suffix.contains("\\"), "Invalid dyld subcache suffix")
            let file = try await APFSFile.open(Self.path + suffix, in: tree)
            let memberHeader = try await add(file)
            try require(try memberHeader.bytes(at: 88, size: 16) == entries.bytes(at: item, size: 16), "Dyld subcache UUID mismatch")
        }
        return (primary, header)
    }

    private func add(_ file: AssetFile) async throws -> Data {
        let header = try await file.read(0, 568)
        try require(try header.cString(at: 0, end: 16) == "dyld_v1  arm64e", "Unsupported dyld cache format")
        let offset = UInt64(try header.integer(at: 312, as: UInt32.self))
        let count = Int(try header.integer(at: 316, as: UInt32.self))
        try require(count > 0 && count <= 64, "Invalid dyld mapping count")
        let table = try await file.read(offset, count * 56)
        for index in 0..<count {
            let item = index * 56
            let address: UInt64 = try table.integer(at: item), size: UInt64 = try table.integer(at: item + 8)
            let offset: UInt64 = try table.integer(at: item + 16)
            let slideOffset: UInt64 = try table.integer(at: item + 24), slideSize: UInt64 = try table.integer(at: item + 32)
            try require(size > 0 && size <= UInt64.max - address && offset <= file.size && size <= file.size - offset
                && slideOffset <= file.size && slideSize <= file.size - slideOffset, "Invalid dyld mapping")
            try require(!mappings.contains { address < $0.address + $0.size && $0.address < address + size },
                        "Overlapping dyld cache mappings")
            mappings.append(.init(file: file, address: address, size: size, offset: offset,
                                  slideOffset: slideOffset, slideSize: slideSize))
        }
        return header
    }

    func mapping(_ address: UInt64) throws -> Mapping {
        guard let result = mappings.first(where: { address >= $0.address && address - $0.address < $0.size }) else {
            throw AnisetteError("Address outside dyld shared cache")
        }
        return result
    }

    private func findImage(_ file: AssetFile, header: Data) async throws -> UInt64 {
        let offset = UInt64(try header.integer(at: 448, as: UInt32.self))
        let count = Int(try header.integer(at: 452, as: UInt32.self))
        try require(count > 0 && count <= 100000, "Invalid dyld image table")
        let table = try await file.read(offset, count * 32)
        for index in 0..<count {
            let pathOffset = UInt64(try table.integer(at: index * 32 + 24, as: UInt32.self))
            try require(pathOffset < file.size, "Invalid dyld image path offset")
            let path = try await file.read(pathOffset, Int(min(4096, file.size - pathOffset)))
            if try path.cString(at: 0, end: path.count) == Self.image { return try table.integer(at: index * 32) }
        }
        throw AnisetteError("AppleMediaServices missing from dyld cache")
    }

    private func symbols(_ image: MachO, file: AssetFile) async throws -> (Data, [MachOExtraction.Region]) {
        guard let command = image.commands.first(where: { $0.kind == UInt32(LC_SYMTAB) }) else {
            throw AnisetteError("Dyld image has no symbols")
        }
        let offset = UInt64(try image.data.integer(at: command.offset + 8, as: UInt32.self))
        let count = Int(try image.data.integer(at: command.offset + 12, as: UInt32.self))
        let stringOffset = UInt64(try image.data.integer(at: command.offset + 16, as: UInt32.self))
        let stringSize = UInt64(try image.data.integer(at: command.offset + 20, as: UInt32.self))
        try require(count <= 1 << 20 && stringOffset <= file.size && stringSize <= file.size - stringOffset,
                    "Invalid dyld symbol table")
        let symbols = try await file.read(offset, count * 16)
        let names = try Set((0..<count).map { UInt64(try symbols.integer(at: $0 * 16, as: UInt32.self)) }).sorted()
        var regions: [MachOExtraction.Region] = []
        var start: UInt64 = 0, end: UInt64 = 0
        for name in names {
            try require(name < stringSize, "Invalid dyld symbol string offset")
            if name >= end {
                if end > start {
                    regions.append(.init(address: start, data: try await file.read(stringOffset + start, Int(end - start))))
                }
                start = name; end = name
            }
            end = min(stringSize, max(end, name + 4096))
        }
        if end > start { regions.append(.init(address: start, data: try await file.read(stringOffset + start, Int(end - start)))) }
        return (symbols, regions)
    }
}
