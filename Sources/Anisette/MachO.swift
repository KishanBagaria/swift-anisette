import Foundation
import MachOKit

/// Anisette's image view over MachOKit layouts and decoders. Bounds and resource
/// limits are checked before calling library APIs that operate on raw pointers.
struct MachO {
    struct Command { let kind: UInt32; let offset: Int; let size: Int }
    struct Segment {
        let name: String
        let address: UInt64
        let size: UInt64
        let offset: Int
        let length: Int
        let command: Int
    }
    struct Section { let name: String; let offset: Int; let size: Int; let flags: UInt32 }
    struct Symbol { let name: String; let type: UInt8; let section: UInt8; let description: UInt16; let value: UInt64 }
    var data: Data
    let commands: [Command]
    let segments: [Segment]
    let sections: [Section]
    let base: UInt64

    init(_ input: Data, validateFileRanges: Bool = true) throws {
        data = Data(input)
        try data.checkRange(0, 32)
        let header = MachHeader(layout: try data.machLayout(at: 0))
        try require(header.layout.magic == 0xfeedfacf && header.layout.cputype == 0x100000c, "Expected ARM64 Mach-O")
        let count = Int(header.layout.ncmds), length = Int(header.layout.sizeofcmds)
        try require(count > 0 && count <= 4096 && length <= 4 << 20, "Invalid Mach-O command table")
        try data.checkRange(32, length)
        var commands: [Command] = [], segments: [Segment] = [], sections: [Section] = []
        var offset = 32
        for _ in 0..<count {
            let command: load_command = try data.machLayout(at: offset)
            let size = Int(command.cmdsize)
            try require(size >= 8 && size % 8 == 0 && offset <= 32 + length - size, "Invalid Mach-O load command")
            commands.append(.init(kind: command.cmd, offset: offset, size: size))
            if command.cmd == UInt32(LC_SEGMENT_64) {
                try require(size >= SegmentCommand64.layoutSize, "Truncated Mach-O segment")
                let segment = SegmentCommand64(try data.machLayout(at: offset), offset: offset - 32)
                let raw = segment.layout
                try require(raw.nsects <= (size - SegmentCommand64.layoutSize) / Section64.layoutSize,
                            "Invalid Mach-O section count")
                try require(raw.fileoff <= Int.max && raw.filesize <= Int.max, "Mach-O file offset exceeds host range")
                let name = segment.segmentName
                if name != "__PAGEZERO" {
                    try require(raw.filesize <= raw.vmsize, "Invalid Mach-O memory span")
                    _ = try guestAddress(raw.vmaddr, offset: raw.vmsize)
                    if validateFileRanges {
                        try require(raw.vmsize <= 1 << 30 && raw.filesize <= 256 << 20, "Mach-O segment exceeds limit")
                        try data.checkRange(Int(raw.fileoff), Int(raw.filesize))
                    }
                }
                segments.append(.init(name: name, address: raw.vmaddr, size: raw.vmsize,
                                      offset: Int(raw.fileoff), length: Int(raw.filesize), command: offset))
                for index in 0..<Int(raw.nsects) {
                    let item = offset + SegmentCommand64.layoutSize + index * Section64.layoutSize
                    let section = Section64(layout: try data.machLayout(at: item))
                    try require(section.layout.size <= Int.max, "Mach-O section exceeds host range")
                    sections.append(.init(name: section.sectionName, offset: Int(section.layout.offset),
                                          size: Int(section.layout.size), flags: section.layout.flags))
                }
            }
            offset += size
        }
        try require(offset == 32 + length, "Mach-O command count does not match its size")
        guard let text = segments.first(where: { $0.name == "__TEXT" }) else { throw AnisetteError("Mach-O has no __TEXT") }
        self.commands = commands; self.segments = segments; self.sections = sections; base = text.address
    }

    func command(_ kind: UInt32, minimum: Int) throws -> Int? {
        guard let command = commands.first(where: { $0.kind == kind }) else { return nil }
        try require(command.size >= minimum, "Truncated Mach-O command")
        return command.offset
    }

    func contains(_ address: UInt64) -> Bool {
        segments.contains { address >= $0.address && address - $0.address < $0.size }
    }

    func symbols(in backing: Data? = nil) throws -> [Symbol] {
        guard let command = try command(UInt32(LC_SYMTAB), minimum: MemoryLayout<symtab_command>.size) else { return [] }
        let table = LoadCommandInfo<symtab_command>(try data.machLayout(at: command), offset: command - 32)
        let bytes = backing ?? data
        try require(table.nsyms <= 1 << 20, "Mach-O symbol count exceeds limit")
        try bytes.checkRange(Int(table.stroff), Int(table.strsize))
        let encoded = try bytes.bytes(at: Int(table.symoff), size: Int(table.nsyms) * Nlist64.layoutSize)
        return try Self.decodeSymbols(encoded) { offset in
            try require(offset < table.strsize, "Mach-O symbol string exceeds table")
            return try bytes.cString(at: Int(table.stroff) + Int(offset), end: Int(table.stroff) + Int(table.strsize))
        }
    }

    static func decodeSymbols(_ data: Data, name: (UInt32) throws -> String) throws -> [Symbol] {
        try require(data.count % Nlist64.layoutSize == 0 && data.count / Nlist64.layoutSize <= 1 << 20,
                    "Invalid Mach-O symbol table")
        return try stride(from: 0, to: data.count, by: Nlist64.layoutSize).map { offset in
            let layout = try data.machLayout(at: offset, into: Nlist64.Layout())
            let symbol = Nlist64(layout: layout).layout
            return try Symbol(name: name(symbol.n_un.n_strx), type: symbol.n_type, section: symbol.n_sect,
                              description: symbol.n_desc, value: symbol.n_value)
        }
    }

    func exports() throws -> [String: UInt64] {
        var result: [String: UInt64] = [:]
        for symbol in try symbols() where symbol.value != 0 { result[symbol.name] = symbol.value }
        let location: (UInt32, UInt32)
        if let command = try command(UInt32(LC_DYLD_EXPORTS_TRIE), minimum: MemoryLayout<linkedit_data_command>.size) {
            let table: linkedit_data_command = try data.machLayout(at: command)
            location = (table.dataoff, table.datasize)
        } else if let command = try command(UInt32(LC_DYLD_INFO_ONLY), minimum: MemoryLayout<dyld_info_command>.size)
                    ?? command(UInt32(LC_DYLD_INFO), minimum: MemoryLayout<dyld_info_command>.size) {
            let table: dyld_info_command = try data.machLayout(at: command)
            location = (table.export_off, table.export_size)
        } else { return result }
        if location.1 == 0 { return result }
        let trie = try data.bytes(at: Int(location.0), size: Int(location.1))
        var pending: [(Int, String, Set<Int>)] = [(0, "", [])], visited = 0
        while let (offset, prefix, ancestors) = pending.popLast() {
            try require(!ancestors.contains(offset) && prefix.utf8.count <= 4096 && visited < 1 << 20,
                        "Invalid Mach-O export trie")
            visited += 1
            let entry = try MachOExport.read(trie, at: offset)
            if let content = entry.content, let flags = content.flags, !flags.contains(.reexport),
               let target = content.symbolOffset ?? content.stub, result[prefix] == nil {
                result[prefix] = try flags.kind == .absolute ? UInt64(target) : guestAddress(base, offset: UInt64(target))
            }
            for child in entry.children {
                pending.append((Int(child.offset), prefix + child.label, ancestors.union([offset])))
            }
        }
        return result
    }
}

extension Data {
    func checkRange(_ offset: Int, _ size: Int) throws {
        try require(offset >= 0 && size >= 0 && offset <= count && size <= count - offset, "Binary range exceeds buffer")
    }
    func bytes(at offset: Int, size: Int) throws -> Data {
        try checkRange(offset, size)
        return subdata(in: offset..<offset + size)
    }
    func cString(at offset: Int, end: Int) throws -> String {
        try require(offset >= 0 && end >= offset && end <= count, "Invalid binary string range")
        try checkRange(offset, end - offset)
        guard let zero = self[offset..<end].firstIndex(of: 0) else { throw AnisetteError("Unterminated binary string") }
        return String(decoding: self[offset..<zero], as: UTF8.self)
    }
    func byte(_ cursor: inout Int) throws -> UInt8 {
        try checkRange(cursor, 1)
        defer { cursor += 1 }
        return self[cursor]
    }
    func uleb(_ cursor: inout Int) throws -> UInt64 {
        var value: UInt64 = 0
        for shift in stride(from: 0, through: 63, by: 7) {
            let byte = try byte(&cursor)
            try require(shift < 63 || byte <= 1, "ULEB128 overflows")
            value |= UInt64(byte & 127) << shift
            if byte & 128 == 0 { return value }
        }
        throw AnisetteError("Invalid ULEB128")
    }
    func sleb(_ cursor: inout Int) throws -> Int64 {
        var value: UInt64 = 0
        for shift in stride(from: 0, through: 63, by: 7) {
            let byte = try byte(&cursor)
            try require(shift < 63 || byte == 0 || byte == 127, "SLEB128 overflows")
            value |= UInt64(byte & 127) << shift
            if byte & 128 == 0 {
                if byte & 64 != 0 && shift < 63 { value |= UInt64.max << (shift + 7) }
                return Int64(bitPattern: value)
            }
        }
        throw AnisetteError("Invalid SLEB128")
    }
}
