import Foundation
import MachOKit

extension MachO {
    mutating func relocate(to address: UInt64, resolve: (String) throws -> UInt64) throws {
        if let chained = try command(UInt32(LC_DYLD_CHAINED_FIXUPS), minimum: 16) {
            let offset = Int(try data.integer(at: chained + 8, as: UInt32.self))
            let size = Int(try data.integer(at: chained + 12, as: UInt32.self))
            if size != 0 { try relocateChains(try data.bytes(at: offset, size: size), to: address, resolve: resolve) }
        } else if let info = try command(UInt32(LC_DYLD_INFO_ONLY), minimum: 48) ?? command(UInt32(LC_DYLD_INFO), minimum: 48) {
            for (field, binding) in [(8, false), (16, true), (24, true), (32, true)] {
                let offset = Int(try data.integer(at: info + field, as: UInt32.self))
                let size = Int(try data.integer(at: info + field + 4, as: UInt32.self))
                if size > 0 {
                    try relocateOpcodes(try data.bytes(at: offset, size: size), binding: binding,
                                        lazy: field == 32, to: address, resolve: resolve)
                }
            }
        }
    }

    mutating func prelink(_ external: [UInt64: UInt64]) throws {
        for segment in segments where segment.name != "__TEXT" && segment.name != "__LINKEDIT" && segment.length >= 8 {
            let start = segment.offset + Int((8 - segment.address % 8) % 8)
            for offset in stride(from: start, through: segment.offset + segment.length - 8, by: 8) {
                let pointer: UInt64 = try data.integer(at: offset)
                if let replacement = external[pointer] { try data.put(replacement, at: offset) }
            }
        }
    }

    mutating func relocateKernel(to address: UInt64, kernelBase: UInt64, resolve: (String) throws -> UInt64) throws {
        var external: [UInt64: String] = [:]
        for symbol in try symbols() where symbol.value != 0 && !contains(symbol.value) { external[symbol.value] = symbol.name }
        for segment in segments where !["__TEXT", "__TEXT_EXEC", "__LINKEDIT"].contains(segment.name) && segment.length >= 8 {
            let start = segment.offset + Int((4 - segment.address % 4) % 4)
            for offset in stride(from: start, through: segment.offset + segment.length - 8, by: 4) {
                let raw: UInt64 = try data.integer(at: offset)
                let target = raw & 0x3fffffff
                if raw >> 30 & 3 != 0 || target == 0 { continue }
                let original = try guestAddress(kernelBase, offset: target)
                if contains(original) {
                    try data.put(guestAddress(address, offset: original - base), at: offset)
                } else if let name = external[original] {
                    try data.put(resolve(name), at: offset)
                }
            }
        }
    }

    private func segmentOffset(_ index: Int, _ offset: UInt64) throws -> Int {
        try require(segments.indices.contains(index), "Fixup segment index exceeds image")
        let segment = segments[index]
        try require(offset <= UInt64(segment.length) && 8 <= UInt64(segment.length) - offset, "Fixup exceeds segment")
        return segment.offset + Int(offset)
    }

    // swiftlint:disable cyclomatic_complexity
    private mutating func relocateOpcodes(_ stream: Data, binding: Bool, lazy: Bool,
                                          to address: UInt64, resolve: (String) throws -> UInt64) throws {
        var cursor = 0, segment = 0
        var offset: UInt64 = 0, type: UInt8 = 1
        var symbol = "", addend: Int64 = 0
        func advance(_ amount: UInt64) throws { offset = try guestAddress(offset, offset: amount) }
        func apply(_ image: inout MachO) throws {
            try require(type == 1, "Unsupported dyld relocation type")
            let location = try image.segmentOffset(segment, offset)
            let value: UInt64
            if binding { value = try addingSigned(resolve(symbol), addend) } else {
                let original: UInt64 = try image.data.integer(at: location)
                try require(original >= image.base, "Rebase precedes Mach-O base")
                value = try guestAddress(address, offset: original - image.base)
            }
            try image.data.put(value, at: location)
            try advance(8)
        }
        while cursor < stream.count {
            let byte = try stream.byte(&cursor), opcode = byte & 0xf0, immediate = byte & 15
            if !binding {
                switch opcode {
                case 0: return
                case 0x10: type = immediate
                case 0x20: segment = Int(immediate); offset = try stream.uleb(&cursor)
                case 0x30: try advance(stream.uleb(&cursor))
                case 0x40: try advance(UInt64(immediate) * 8)
                case 0x50, 0x60:
                    let count = try opcode == 0x50 ? UInt64(immediate) : stream.uleb(&cursor)
                    try require(count <= UInt64(data.count / 8), "Rebase count exceeds image")
                    for _ in 0..<count { try apply(&self) }
                case 0x70: try apply(&self); try advance(stream.uleb(&cursor))
                case 0x80:
                    let count = try stream.uleb(&cursor), skip = try stream.uleb(&cursor)
                    try require(count <= UInt64(data.count / 8), "Rebase count exceeds image")
                    for _ in 0..<count { try apply(&self); try advance(skip) }
                default: throw AnisetteError("Unsupported dyld rebase opcode")
                }
                continue
            }
            switch opcode {
            case 0:
                if !lazy { return }
                segment = 0; offset = 0; type = 1; symbol = ""; addend = 0
            case 0x10, 0x30: break // Library ordinals do not affect our resolver.
            case 0x20: _ = try stream.uleb(&cursor)
            case 0x40:
                symbol = try stream.cString(at: cursor, end: stream.count)
                cursor += symbol.utf8.count + 1
            case 0x50: type = immediate
            case 0x60: addend = try stream.sleb(&cursor)
            case 0x70: segment = Int(immediate); offset = try stream.uleb(&cursor)
            case 0x80: try advance(stream.uleb(&cursor))
            case 0x90: try apply(&self)
            case 0xa0: try apply(&self); try advance(stream.uleb(&cursor))
            case 0xb0: try apply(&self); try advance(UInt64(immediate) * 8)
            case 0xc0:
                let count = try stream.uleb(&cursor), skip = try stream.uleb(&cursor)
                try require(count <= UInt64(data.count / 8), "Bind count exceeds image")
                for _ in 0..<count { try apply(&self); try advance(skip) }
            default: throw AnisetteError("Unsupported dyld bind opcode")
            }
        }
    }
    // swiftlint:enable cyclomatic_complexity

    private mutating func relocateChains(_ fixups: Data, to address: UInt64, resolve: (String) throws -> UInt64) throws {
        let header = DyldChainedFixupsHeader(layout: try fixups.machLayout(at: 0))
        try require(header.fixups_version == 0, "Unsupported chained fixup version")
        let starts = Int(header.starts_offset)
        let imports = try chainedImports(fixups, header: header)
        let count = Int(try fixups.integer(at: starts, as: UInt32.self))
        try require(count <= segments.count, "Chained fixup segments exceed image")
        try fixups.checkRange(starts + 4, count * 4)
        for index in 0..<count {
            let relative = Int(try fixups.integer(at: starts + 4 + index * 4, as: UInt32.self))
            if relative == 0 { continue }
            let table = starts + relative
            let size = Int(try fixups.integer(at: table, as: UInt32.self))
            try fixups.checkRange(table, size)
            let pageSize = Int(try fixups.integer(at: table + 4, as: UInt16.self))
            let format: UInt16 = try fixups.integer(at: table + 6)
            let pages = Int(try fixups.integer(at: table + 20, as: UInt16.self))
            try require(size >= 22 && pageSize >= 4096 && pages <= (size - 22) / 2, "Invalid chained page table")
            for page in 0..<pages {
                let start: UInt16 = try fixups.integer(at: table + 22 + page * 2)
                if start == 0xffff { continue }
                try require(start & 0x8000 == 0, "Unsupported multi-start chained page")
                var offset = Int(start)
                while true {
                    try require(offset <= pageSize - 8, "Chained fixup leaves page")
                    let location = try segmentOffset(index, UInt64(page * pageSize + offset))
                    let raw: UInt64 = try data.integer(at: location)
                    let decoded = try decodeChain(raw, format: format, address: address, imports: imports, resolve: resolve)
                    try data.put(decoded.value, at: location)
                    if decoded.next == 0 { break }
                    offset += decoded.next
                }
            }
        }
    }

    private func chainedImports(_ fixups: Data, header: DyldChainedFixupsHeader) throws -> [(String, Int64)] {
        let offset = Int(header.imports_offset), strings = Int(header.symbols_offset), count = Int(header.imports_count)
        let format = header.imports_format
        try require(count <= 1 << 20 && [1, 2, 3].contains(format) && header.symbols_format == 0, "Unsupported chained imports")
        let stride = format == 1 ? 4 : (format == 2 ? 8 : 16)
        try fixups.checkRange(offset, count * stride)
        return try (0..<count).map { index in
            let item = offset + index * stride
            let symbol: DyldChainedImport
            if format == 3 {
                symbol = .addend64(.init(layout: try fixups.machLayout(at: item, into: DyldChainedImportAddend64.Layout())))
            } else if format == 2 {
                symbol = .addend(.init(layout: try fixups.machLayout(at: item, into: DyldChainedImportAddend.Layout())))
            } else {
                symbol = .general(.init(layout: try fixups.machLayout(at: item, into: DyldChainedImportGeneral.Layout())))
            }
            let info = symbol.info
            try require(info.nameOffset < fixups.count && strings <= fixups.count - info.nameOffset,
                        "Invalid chained import name")
            return (try fixups.cString(at: strings + info.nameOffset, end: fixups.count), Int64(info.addend))
        }
    }

    private func decodeChain(_ raw: UInt64, format: UInt16, address: UInt64,
                             imports: [(String, Int64)], resolve: (String) throws -> UInt64) throws -> (value: UInt64, next: Int) {
        let arm = [UInt16(1), 7, 9, 10, 12].contains(format)
        guard arm || format == 2 || format == 6,
              let pointerFormat = DyldChainedFixupPointerFormat(rawValue: format),
              let pointer = DyldChainedFixupPointerInfo(rawValue: raw, pointerFormat: pointerFormat) else {
            throw AnisetteError("Unsupported chained pointer format \(format)")
        }
        let next = pointer.nextOffset
        if let bind = pointer.bind {
            try require(imports.indices.contains(bind.ordinal), "Chained import ordinal exceeds table")
            let (symbol, importedAddend) = imports[bind.ordinal]
            let addend = Int64(bitPattern: arm ? bind.signExtendedAddend : bind.addend)
            let (total, overflow) = importedAddend.addingReportingOverflow(addend)
            try require(!overflow, "Chained addend overflow")
            return (try addingSigned(resolve(symbol), total), next)
        }
        guard let rebase = pointer.rebase else { throw AnisetteError("Missing chained pointer target") }
        var target = arm ? UInt64(rebase.target) : rebase.unpackedTarget
        if format == 2 || (format == 1 && !rebase.isAuth) {
            if arm { target &= 0x00ffffffffffffff }
            try require(target >= base, "Chained rebase precedes image base")
            target -= base
        }
        return (try guestAddress(address, offset: target), next)
    }
}

func addingSigned(_ value: UInt64, _ offset: Int64) throws -> UInt64 {
    if offset >= 0 { return try guestAddress(value, offset: UInt64(offset)) }
    try require(value >= offset.magnitude, "Signed address underflow")
    return value - offset.magnitude
}
