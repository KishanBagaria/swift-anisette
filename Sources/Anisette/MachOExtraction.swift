import Foundation
import MachOKit

/// Builds standalone Mach-O files from downloaded source bytes. Headers and
/// link-edit contents are interpreted here, rather than shipped as literal patches.
enum MachOExtraction {
    struct Region { let address: UInt64; let data: Data }

    static func dyld(header: Data, segments: [Region], exports: Data, slides: [Region],
                     symbols: Data, strings: [Region]) throws -> Data {
        let image = try MachO(header, validateFileRanges: false)
        let layout = image.segments.filter { $0.name != "__LINKEDIT" && $0.length > 0 }
        try require(layout.count == segments.count, "Shared-cache segment count changed")
        var bytes: [String: Data] = [:]
        var pages: [MachO.Segment] = []
        for (segment, original) in zip(layout, segments) {
            try require(segment.address >= original.address, "Shared-cache segment precedes downloaded pages")
            try original.data.checkRange(Int(segment.address - original.address), segment.length)
            bytes[segment.name] = original.data
            pages.append(.init(name: segment.name, address: original.address, size: UInt64(original.data.count),
                               offset: 0, length: original.data.count, command: 0))
        }
        for slide in slides { try applySlide(slide, segments: pages, bytes: &bytes) }
        for (segment, page) in zip(layout, pages) {
            bytes[segment.name] = try bytes[segment.name]!.bytes(at: Int(segment.address - page.address), size: segment.length)
        }
        return try normalize(image, segments: bytes, symbols: decodeSymbols(symbols, strings: strings), exports: exports)
    }

    private static func decodeSymbols(_ data: Data, strings: [Region]) throws -> [MachO.Symbol] {
        try MachO.decodeSymbols(data) { offset in
            let start = UInt64(offset)
            guard let source = strings.first(where: { start >= $0.address && start - $0.address < $0.data.count }) else {
                throw AnisetteError("Missing downloaded symbol string")
            }
            let location = Int(start - source.address)
            var name = try source.data.cString(at: location, end: min(source.data.count, location + 4096))
            if name.hasPrefix("_") && name.contains(".") { name.removeFirst() }
            return name
        }
    }

    static func kernel(_ collection: Data) throws -> Data {
        let outer = try MachO(collection)
        var members: [MachO] = []
        var selected: MachO?
        for command in outer.commands where command.kind == UInt32(LC_FILESET_ENTRY) {
            try require(command.size >= FilesetEntryCommand.layoutSize, "Truncated kernel fileset entry")
            let layout = try collection.machLayout(at: command.offset, into: FilesetEntryCommand.Layout())
            let entry = FilesetEntryCommand(layout, offset: command.offset - 32)
            let nameOffset = Int(entry.layout.entry_id.offset)
            try require(nameOffset >= FilesetEntryCommand.layoutSize && nameOffset < command.size, "Invalid fileset name")
            let name = try collection.cString(at: command.offset + nameOffset, end: command.offset + command.size)
            try require(entry.layout.fileoff <= Int.max, "Kernel fileset offset exceeds host range")
            let offset = Int(entry.layout.fileoff)
            let member = try MachO(header(in: collection, at: offset), validateFileRanges: false)
            members.append(member)
            if name == "com.apple.driver.FairPlayIOKit" { selected = member }
        }
        guard let image = selected else { throw AnisetteError("Kernel collection has no FairPlayIOKit") }
        var symbols = try image.symbols(in: collection)
        let undefined = Set(symbols.filter { $0.type & 0x0e == 0 && !$0.name.isEmpty }.map(\.name))
        var resolved: [String: MachO.Symbol] = [:]
        for member in members {
            for symbol in try member.symbols(in: collection) where undefined.contains(symbol.name)
                && symbol.type & 1 != 0 && symbol.type & 0x0e != 0 && symbol.value != 0 {
                resolved[symbol.name] = symbol
            }
        }
        for symbol in symbols where undefined.contains(symbol.name) {
            if let definition = resolved[symbol.name] {
                symbols.append(.init(name: symbol.name, type: 3, section: 0, description: symbol.description, value: definition.value))
            }
        }
        var bytes: [String: Data] = [:]
        for segment in image.segments where segment.name != "__LINKEDIT" && segment.length > 0 {
            bytes[segment.name] = try collection.bytes(at: segment.offset, size: segment.length)
        }
        return try normalize(image, segments: bytes, symbols: symbols, exports: Data())
    }

    private static func header(in data: Data, at offset: Int) throws -> Data {
        try data.checkRange(offset, 32)
        let size = Int(try data.integer(at: offset + 20, as: UInt32.self))
        try require(size <= 4 << 20, "Kernel command table exceeds limit")
        return try data.bytes(at: offset, size: 32 + size)
    }

    private static func applySlide(_ slide: Region, segments: [MachO.Segment], bytes: inout [String: Data]) throws {
        let data = slide.data
        try require(try data.integer(at: 0, as: UInt32.self) == 5, "Unsupported dyld slide version")
        let size = UInt64(try data.integer(at: 4, as: UInt32.self))
        let count = Int(try data.integer(at: 8, as: UInt32.self))
        let valueAdd: UInt64 = try data.integer(at: 16)
        try require(size >= 4096 && size <= 65536, "Invalid dyld slide page size")
        try data.checkRange(24, count * 2)
        for segment in segments {
            if segment.address < slide.address || segment.length < 8 { continue }
            let startPage = (segment.address - slide.address) / size
            if startPage >= count { continue }
            let end = try guestAddress(segment.address, offset: UInt64(segment.length))
            let endPage = min(UInt64(count), (end - slide.address + size - 1) / size)
            for page in startPage..<endPage {
                let start: UInt16 = try data.integer(at: 24 + Int(page) * 2)
                if start == 0xffff { continue }
                var offset = UInt64(start)
                while true {
                    try require(offset <= size - 8, "Dyld slide chain leaves page")
                    let address = try guestAddress(slide.address, offset: page * size + offset)
                    // The downloaded segment covers the complete pages used by this image.
                    try require(address >= segment.address && address - segment.address <= UInt64(segment.length - 8),
                                "Dyld slide pointer has no downloaded backing")
                    let index = Int(address - segment.address)
                    let raw: UInt64 = try bytes[segment.name]!.integer(at: index)
                    guard let pointer = DyldChainedFixupPointerInfo(rawValue: raw, pointerFormat: .arm64e_shared_cache),
                          let rebase = pointer.rebase else { throw AnisetteError("Invalid shared-cache pointer") }
                    let target = rebase.unpackedTarget
                    try bytes[segment.name]!.put(raw == 0 ? UInt64(0) : guestAddress(valueAdd, offset: target), at: index)
                    let next = UInt64(pointer.next)
                    if next == 0 { break }
                    offset += next * 8
                }
            }
        }
    }

    // swiftlint:disable cyclomatic_complexity
    private static func normalize(_ image: MachO, segments: [String: Data], symbols: [MachO.Symbol], exports: Data) throws -> Data {
        var header = image.data
        try header.put(try header.integer(at: 24, as: UInt32.self) & 0x7fffffff, at: 24)
        var offsets: [String: Int] = [:], total = 0
        for segment in image.segments where segment.name != "__LINKEDIT" {
            offsets[segment.name] = total
            total += Int(try guestAligned(UInt64(segment.length), to: 16384))
        }
        try require(total <= 256 << 20, "Extracted Mach-O exceeds limit")
        let linkOffset = total
        var nlists = Data(), strings = Data([0])
        for symbol in symbols {
            try require(strings.count <= (64 << 20) - symbol.name.utf8.count - 1, "Extracted symbol strings exceed limit")
            nlists.append(.littleEndian(UInt32(strings.count)))
            nlists.append(contentsOf: [symbol.type, symbol.section])
            nlists.append(.littleEndian(symbol.description)); nlists.append(.littleEndian(symbol.value))
            strings.append(contentsOf: symbol.name.utf8); strings.append(0)
        }
        let stringOffset = linkOffset + nlists.count
        let exportOffset = stringOffset + strings.count
        let linkedit = nlists + strings + exports
        offsets["__LINKEDIT"] = linkOffset
        for command in image.commands {
            let item = command.offset
            switch command.kind {
            case UInt32(LC_SEGMENT_64):
                guard let segment = image.segments.first(where: { $0.command == item }), let offset = offsets[segment.name] else {
                    throw AnisetteError("Missing extracted segment")
                }
                try header.put(UInt64(offset), at: item + 40)
                if segment.name == "__LINKEDIT" {
                    try header.put(UInt64(linkedit.count), at: item + 48)
                    try header.put(guestAligned(UInt64(linkedit.count), to: 16384), at: item + 32)
                }
                let count = Int(try header.integer(at: item + 64, as: UInt32.self))
                for index in 0..<count {
                    let section = item + 72 + index * 80
                    let address: UInt64 = try header.integer(at: section + 32)
                    let flags: UInt32 = try header.integer(at: section + 64)
                    let zeroFill = [UInt32(1), 0xc, 0x12].contains(flags & 255)
                    try require(zeroFill || (address >= segment.address && address - segment.address <= segment.size),
                                "Section exceeds segment")
                    try header.put(zeroFill ? UInt32(0) : UInt32(offset + Int(address - segment.address)), at: section + 48)
                    try header.put(UInt32(0), at: section + 56); try header.put(UInt32(0), at: section + 60)
                }
            case UInt32(LC_SYMTAB):
                try require(command.size >= 24, "Truncated symbol command")
                try header.put(UInt32(linkOffset), at: item + 8); try header.put(UInt32(symbols.count), at: item + 12)
                try header.put(UInt32(stringOffset), at: item + 16); try header.put(UInt32(strings.count), at: item + 20)
            case UInt32(LC_DYSYMTAB):
                header.replaceSubrange(item + 8..<item + command.size, with: Data(count: command.size - 8))
            case UInt32(LC_DYLD_INFO), UInt32(LC_DYLD_INFO_ONLY):
                try require(command.size >= 48, "Truncated dyld info")
                header.replaceSubrange(item + 8..<item + 48, with: Data(count: 40))
                try header.put(UInt32(exportOffset), at: item + 40); try header.put(UInt32(exports.count), at: item + 44)
            case UInt32(LC_DYLD_EXPORTS_TRIE):
                try require(command.size >= 16, "Truncated export command")
                try header.put(UInt32(exportOffset), at: item + 8); try header.put(UInt32(exports.count), at: item + 12)
            case UInt32(LC_CODE_SIGNATURE), UInt32(LC_SEGMENT_SPLIT_INFO), UInt32(LC_FUNCTION_STARTS),
                 UInt32(LC_DATA_IN_CODE), UInt32(LC_DYLIB_CODE_SIGN_DRS), UInt32(LC_LINKER_OPTIMIZATION_HINT),
                 UInt32(LC_DYLD_CHAINED_FIXUPS):
                try require(command.size >= 16, "Truncated link-edit command")
                try header.put(UInt64(0), at: item + 8)
            default: break
            }
        }
        var output = Data(count: linkOffset)
        for segment in image.segments where segment.name != "__LINKEDIT" && segment.length > 0 {
            guard let data = segments[segment.name], let offset = offsets[segment.name], data.count == segment.length else {
                throw AnisetteError("Missing extracted segment data")
            }
            output.replaceSubrange(offset..<offset + data.count, with: data)
        }
        try require(header.count <= output.count, "Extracted header exceeds __TEXT")
        output.replaceSubrange(0..<header.count, with: header)
        output.append(linkedit)
        _ = try MachO(output)
        return output
    }
    // swiftlint:enable cyclomatic_complexity
}
