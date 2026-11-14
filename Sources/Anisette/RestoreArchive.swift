import Foundation

/// ZIP/ZIP64 directory discovery over HTTP ranges. Encrypted disk images are
/// stored members and remain seekable; only the small kernel member is inflated.
struct RestoreArchive {
    struct Entry {
        let name: String
        let method: UInt16
        let compressed: UInt64
        let size: UInt64
        let offset: UInt64
        let crc: UInt32
        /// Unix archives record the file mode; anything but a regular file is rejected on extraction.
        let isRegularFile: Bool
    }
    let source: AssetFile
    let entries: [Entry]

    static func open(_ source: AssetFile) async throws -> Self {
        let tail = try tailOffset(source.size)
        let directory: Directory
        switch try await endRecord(source.read(tail, Int(source.size - tail)), at: tail) {
        case .directory(let found): directory = found
        case .zip64(let locator): directory = try await zip64(source.read(zip64Record(source.read(locator, 20)), 56))
        }
        return Self(source: source, entries: try await parse(source.read(directory.offset, directory.size), count: directory.count))
    }

    /// A member pinned by its exact sizes. Stored members stay seekable and are not read here.
    func member(_ name: String, compressed: UInt64, size: UInt64) async throws -> AssetFile {
        let entry = try Self.entry(name, in: entries)
        try require(entry.compressed == compressed && entry.size == size
            && entry.method == (compressed == size ? 0 : 8), "Restore member \(name) does not match pinned build")
        let file = try source.section(Self.dataOffset(entry, header: await source.read(entry.offset, Self.headerSize(entry))),
                                      entry.compressed)
        if entry.method == 0 { return file }
        return try await .memory(file.read(0, Int(entry.compressed)).inflated(size: Int(entry.size)))
    }

    /// Reads a whole regular-file member of an in-memory archive and checks its declared size and CRC-32.
    static func contents(of name: String, in archive: Data, limit: UInt64) throws -> Data {
        let archive = Data(archive), size = UInt64(archive.count)
        let tail = try tailOffset(size)
        let directory: Directory
        switch try endRecord(archive.range(tail, Int(size - tail)), at: tail) {
        case .directory(let found): directory = found
        case .zip64(let locator): directory = try zip64(archive.range(zip64Record(archive.range(locator, 20)), 56))
        }
        let entry = try entry(name, in: parse(archive.range(directory.offset, directory.size), count: directory.count))
        try require(entry.isRegularFile && entry.size > 0 && entry.size <= limit && entry.compressed <= size,
                    "ZIP member \(name) exceeds limits")
        let raw = try archive.range(dataOffset(entry, header: archive.range(entry.offset, headerSize(entry))), Int(entry.compressed))
        let data = entry.method == 0 ? raw : try raw.inflated(size: Int(entry.size))
        try require(data.crc32 == entry.crc, "ZIP member \(name) failed integrity verification")
        return data
    }

    private struct Directory {
        let count: UInt64, size: Int, offset: UInt64

        init(count: UInt64, size: UInt64, offset: UInt64) throws {
            try require(count <= 100000 && size <= 32 << 20, "ZIP directory exceeds limit")
            self.count = count; self.size = Int(size); self.offset = offset
        }
    }

    private enum End { case directory(Directory), zip64(locator: UInt64) }

    /// Start of the region holding the end record and its maximal comment.
    private static func tailOffset(_ size: UInt64) throws -> UInt64 {
        try require(size >= 22, "Truncated ZIP archive")
        return size - min(size, 65557)
    }

    private static func endRecord(_ tail: Data, at tailOffset: UInt64) throws -> End {
        guard let end = try stride(from: tail.count - 22, through: 0, by: -1).first(where: {
            try tail.integer(at: $0, as: UInt32.self) == 0x06054b50
                && $0 + 22 + Int(tail.integer(at: $0 + 20, as: UInt16.self)) == tail.count
        }) else { throw AnisetteError("ZIP end record missing") }
        try require(try tail.integer(at: end + 4, as: UInt32.self) == 0, "Multi-disk ZIP is unsupported")
        let count = UInt64(try tail.integer(at: end + 10, as: UInt16.self))
        let size = UInt64(try tail.integer(at: end + 12, as: UInt32.self))
        let offset = UInt64(try tail.integer(at: end + 16, as: UInt32.self))
        guard count == 0xffff || size == 0xffffffff || offset == 0xffffffff else {
            return .directory(try Directory(count: count, size: size, offset: offset))
        }
        let endOffset = tailOffset + UInt64(end)
        try require(endOffset >= 20, "Missing ZIP64 locator")
        return .zip64(locator: endOffset - 20)
    }

    private static func zip64Record(_ locator: Data) throws -> UInt64 {
        try require(try locator.integer(at: 0, as: UInt32.self) == 0x07064b50
            && locator.integer(at: 4, as: UInt32.self) == 0
            && locator.integer(at: 16, as: UInt32.self) == 1, "Invalid ZIP64 locator")
        return try locator.integer(at: 8)
    }

    private static func zip64(_ record: Data) throws -> Directory {
        try require(try record.integer(at: 0, as: UInt32.self) == 0x06064b50
            && record.integer(at: 16, as: UInt64.self) == 0, "Invalid ZIP64 record")
        return try Directory(count: record.integer(at: 32), size: record.integer(at: 40), offset: record.integer(at: 48))
    }

    private static func parse(_ directory: Data, count: UInt64) throws -> [Entry] {
        var position = 0, entries: [Entry] = []
        for _ in 0..<count {
            try require(try directory.integer(at: position, as: UInt32.self) == 0x02014b50, "Invalid ZIP directory entry")
            let flags: UInt16 = try directory.integer(at: position + 8)
            try require(flags & 1 == 0, "Encrypted ZIP members are unsupported")
            let nameLength = Int(try directory.integer(at: position + 28, as: UInt16.self))
            let extraLength = Int(try directory.integer(at: position + 30, as: UInt16.self))
            let commentLength = Int(try directory.integer(at: position + 32, as: UInt16.self))
            let name = String(decoding: try directory.bytes(at: position + 46, size: nameLength), as: UTF8.self)
            var compressed = UInt64(try directory.integer(at: position + 20, as: UInt32.self))
            var length = UInt64(try directory.integer(at: position + 24, as: UInt32.self))
            var local = UInt64(try directory.integer(at: position + 42, as: UInt32.self))
            let extra = try directory.bytes(at: position + 46 + nameLength, size: extraLength)
            var cursor = 0
            while cursor < extra.count {
                let kind: UInt16 = try extra.integer(at: cursor)
                let extraSize = Int(try extra.integer(at: cursor + 2, as: UInt16.self))
                try extra.checkRange(cursor + 4, extraSize)
                if kind == 1 {
                    let values = try extra.bytes(at: cursor + 4, size: extraSize)
                    try zip64(values, size: &length, compressed: &compressed, offset: &local)
                }
                cursor += 4 + extraSize
            }
            let host = try directory.integer(at: position + 4, as: UInt16.self) >> 8
            let mode = try directory.integer(at: position + 38, as: UInt32.self) >> 16
            let regular = !name.hasSuffix("/") && (host != 3 || mode & 0o170000 == 0 || mode & 0o170000 == 0o100000)
            entries.append(.init(name: name, method: try directory.integer(at: position + 10),
                                 compressed: compressed, size: length, offset: local,
                                 crc: try directory.integer(at: position + 16), isRegularFile: regular))
            position += 46 + nameLength + extraLength + commentLength
            try directory.checkRange(position, 0)
        }
        try require(position == directory.count, "Unexpected ZIP directory data")
        return entries
    }

    private static func zip64(_ data: Data, size: inout UInt64, compressed: inout UInt64, offset: inout UInt64) throws {
        var cursor = 0
        if size == 0xffffffff { size = try data.integer(at: cursor); cursor += 8 }
        if compressed == 0xffffffff { compressed = try data.integer(at: cursor); cursor += 8 }
        if offset == 0xffffffff { offset = try data.integer(at: cursor) }
    }

    private static func entry(_ name: String, in entries: [Entry]) throws -> Entry {
        let matches = entries.filter { $0.name == name }
        try require(matches.count == 1, "Missing or duplicate ZIP member \(name)")
        return matches[0]
    }

    /// The local header plus the member's expected name, which it must repeat. Checks the encoding first,
    /// so only bounded deflated members are ever read whole.
    private static func headerSize(_ entry: Entry) throws -> Int {
        try require(entry.method == 8 || (entry.method == 0 && entry.compressed == entry.size), "Unsupported ZIP member encoding")
        try require(entry.method == 0 || (entry.compressed <= 64 << 20 && entry.size <= 256 << 20),
                    "Compressed ZIP member exceeds limit")
        return 30 + entry.name.utf8.count
    }

    private static func dataOffset(_ entry: Entry, header: Data) throws -> UInt64 {
        let name = Data(entry.name.utf8)
        try require(try header.integer(at: 0, as: UInt32.self) == 0x04034b50
            && header.integer(at: 8, as: UInt16.self) == entry.method, "Invalid ZIP local header")
        try require(Int(try header.integer(at: 26, as: UInt16.self)) == name.count
            && header.bytes(at: 30, size: name.count) == name, "ZIP local member name mismatch")
        let extra = Int(try header.integer(at: 28, as: UInt16.self))
        let (offset, overflow) = entry.offset.addingReportingOverflow(UInt64(30 + name.count + extra))
        try require(!overflow, "ZIP member offset overflow")
        return offset
    }
}

private extension Data {
    func range(_ offset: UInt64, _ count: Int) throws -> Data {
        try require(count >= 0 && offset <= UInt64(self.count) && UInt64(count) <= UInt64(self.count) - offset,
                    "Archive read exceeds bounds")
        return try bytes(at: Int(offset), size: count)
    }
}
