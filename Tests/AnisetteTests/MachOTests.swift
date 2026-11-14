#if os(macOS) || os(Linux)
import Foundation
import Testing
@testable import Anisette

struct MachOTests {
    private let preferred: UInt64 = 0x100000000

    private func image(commands extra: [Data] = []) throws -> Data {
        var header = Data(count: 32)
        try header.put(UInt32(0xfeedfacf), at: 0); try header.put(UInt32(0x100000c), at: 4)
        try header.put(UInt32(3 + extra.count), at: 16)
        try header.put(UInt32(3 * 72 + extra.reduce(0) { $0 + $1.count }), at: 20)
        for (index, name) in ["__TEXT", "__DATA", "__LINKEDIT"].enumerated() {
            var segment = Data(count: 72)
            try segment.put(UInt32(0x19), at: 0); try segment.put(UInt32(72), at: 4)
            segment.replaceSubrange(8..<8 + name.utf8.count, with: name.utf8)
            try segment.put(preferred + UInt64(index * 4096), at: 24)
            try segment.put(UInt64(4096), at: 32); try segment.put(UInt64(index * 4096), at: 40)
            try segment.put(UInt64(4096), at: 48)
            header.append(segment)
        }
        for command in extra { header.append(command) }
        header.append(Data(count: 12288 - header.count))
        return header
    }

    @Test func malformedLoadCommandsFailBeforeAccessingSegments() throws {
        var bytes = try image()
        try bytes.put(UInt32(0), at: 36)
        #expect(throws: (any Error).self) { try MachO(bytes) }
        bytes = try image()
        try bytes.put(UInt32.max, at: 20)
        #expect(throws: (any Error).self) { try MachO(bytes) }
        bytes = try image()
        try bytes.put(UInt64.max, at: 32 + 40)
        #expect(throws: (any Error).self) { try MachO(bytes) }
        #expect(throws: (any Error).self) { try MachO(Data(count: 8)) }
    }

    @Test func dyldOpcodesApplyRebasesAndSignedBindAddends() throws {
        let rebase = Data([0x11, 0x21, 0, 0x51, 0])
        let bind = Data([0x11, 0x40]) + Data("_target\0".utf8) + Data([0x51, 0x60, 0x7c, 0x71, 8, 0x90, 0])
        var info = Data(count: 48)
        try info.put(UInt32(0x80000022), at: 0); try info.put(UInt32(48), at: 4)
        try info.put(UInt32(8192), at: 8); try info.put(UInt32(rebase.count), at: 12)
        try info.put(UInt32(8192 + rebase.count), at: 16); try info.put(UInt32(bind.count), at: 20)
        var bytes = try image(commands: [info])
        try bytes.put(preferred + 256, at: 4096)
        bytes.replaceSubrange(8192..<8192 + rebase.count + bind.count, with: rebase + bind)
        var macho = try MachO(bytes)
        try macho.relocate(to: 0x300000000) { name in
            #expect(name == "_target")
            return 0x500
        }
        #expect(try macho.data.integer(at: 4096, as: UInt64.self) == 0x300000100)
        #expect(try macho.data.integer(at: 4104, as: UInt64.self) == 0x4fc)
        bytes[8192 + 1] = 0x2f
        var invalid = try MachO(bytes)
        #expect(throws: (any Error).self) { try invalid.relocate(to: 0x300000000) { _ in 0 } }
    }

    private func chainedImage(format: UInt16, raw: UInt64, pageStart: UInt16 = 0,
                              importFormat: UInt32 = 2, addend: Int64 = -4) throws -> Data {
        let strings = importFormat == 3 ? 84 : 76
        var fixups = Data(count: strings + 8)
        try fixups.put(UInt32(28), at: 4); try fixups.put(UInt32(68), at: 8)
        try fixups.put(UInt32(strings), at: 12); try fixups.put(UInt32(1), at: 16)
        try fixups.put(importFormat, at: 20); try fixups.put(UInt32(3), at: 28)
        try fixups.put(UInt32(16), at: 36)
        try fixups.put(UInt32(24), at: 44); try fixups.put(UInt16(4096), at: 48)
        try fixups.put(format, at: 50); try fixups.put(UInt64(4096), at: 52)
        try fixups.put(UInt16(1), at: 64); try fixups.put(pageStart, at: 66)
        if importFormat == 3 { try fixups.put(UInt64(bitPattern: addend), at: 76) } else {
            try fixups.put(UInt32(bitPattern: Int32(addend)), at: 72)
        }
        fixups.replaceSubrange(strings..<strings + 8, with: Data("_target\0".utf8))
        var command = Data(count: 16)
        try command.put(UInt32(0x80000034), at: 0); try command.put(UInt32(16), at: 4)
        try command.put(UInt32(8192), at: 8); try command.put(UInt32(fixups.count), at: 12)
        var bytes = try image(commands: [command])
        bytes.replaceSubrange(8192..<8192 + fixups.count, with: fixups)
        try bytes.put(raw, at: 4096)
        return bytes
    }

    @Test func chainedPointerTargetsAndImportedAddends() throws {
        var rebase = try MachO(chainedImage(format: 6, raw: 0x100))
        try rebase.relocate(to: 0x300000000) { _ in 0 }
        #expect(try rebase.data.integer(at: 4096, as: UInt64.self) == 0x300000100)
        var bind = try MachO(chainedImage(format: 6, raw: 1 << 63 | 3 << 24))
        try bind.relocate(to: 0x300000000) { name in
            #expect(name == "_target")
            return 0x500
        }
        #expect(try bind.data.integer(at: 4096, as: UInt64.self) == 0x4ff)
        var armBind = try MachO(chainedImage(format: 9, raw: 1 << 62 | 0x7ffff << 32))
        try armBind.relocate(to: 0x300000000) { _ in 0x500 }
        #expect(try armBind.data.integer(at: 4096, as: UInt64.self) == 0x4fb)
    }

    @Test func chainedImportsPreserveSigned64BitAddends() throws {
        var image = try MachO(chainedImage(format: 6, raw: 1 << 63, importFormat: 3, addend: .min))
        try image.relocate(to: 0x300000000) { _ in UInt64(Int64.min.magnitude) + 1 }
        #expect(try image.data.integer(at: 4096, as: UInt64.self) == 1)
    }

    @Test func chainedPointersRejectUnknownFormatsOrdinalsAndPageEscapes() throws {
        for (format, raw, start) in [(UInt16(99), UInt64(0), UInt16(0)), (6, 0, 4092), (6, 1 << 63 | 2, 0)] {
            var macho = try MachO(chainedImage(format: format, raw: raw, pageStart: start))
            #expect(throws: (any Error).self) { try macho.relocate(to: 0x300000000) { _ in 0 } }
        }
    }

    @Test func exportsComeFromDownloadedTrieAndCyclesAreRejected() throws {
        let trie = Data([0, 1]) + Data("_foo\0".utf8) + Data([8, 3, 0, 0x80, 2, 0])
        var command = Data(count: 16)
        try command.put(UInt32(0x80000033), at: 0); try command.put(UInt32(16), at: 4)
        try command.put(UInt32(8192), at: 8); try command.put(UInt32(trie.count), at: 12)
        var bytes = try image(commands: [command])
        bytes.replaceSubrange(8192..<8192 + trie.count, with: trie)
        #expect(try MachO(bytes).exports()["_foo"] == preferred + 256)
        bytes[8192 + 7] = 0
        #expect(throws: (any Error).self) { try MachO(bytes).exports() }
    }

    @Test func symbolsPreserveHighBitsAndCheckStringOffsets() throws {
        var command = Data(count: 24)
        try command.put(UInt32(2), at: 0); try command.put(UInt32(24), at: 4)
        try command.put(UInt32(8192), at: 8); try command.put(UInt32(1), at: 12)
        try command.put(UInt32(8208), at: 16); try command.put(UInt32(8), at: 20)
        var bytes = try image(commands: [command])
        bytes[8196] = 3
        try bytes.put(UInt16.max, at: 8198); try bytes.put(UInt64.max, at: 8200)
        bytes.replaceSubrange(8208..<8216, with: Data("_target\0".utf8))
        let symbol = try #require(MachO(bytes).symbols().first)
        #expect(symbol.value == .max)
        #expect(symbol.description == .max)
        try bytes.put(UInt32(8), at: 8192)
        #expect(throws: (any Error).self) { try MachO(bytes).symbols() }
    }

    @Test func malformedExportNodesFailBeforeLibraryPointerReads() throws {
        for bytes: [UInt8] in [
            [0x80], [6, 0x80, 0x80, 0x80, 0x80, 8, 0, 0],
            [3, 8, 0, 0x61, 0], [2, 16, 1, 0], [0, 1, 0x61], [0, 1, 0x61, 0, 0x80],
        ] {
            #expect(throws: (any Error).self) { try MachOExport.read(Data(bytes), at: 0) }
        }
    }

    @Test func variableLengthIntegersRejectOverflowAndTruncation() throws {
        var cursor = 0
        #expect(throws: (any Error).self) { try Data(repeating: 255, count: 10).uleb(&cursor) }
        cursor = 0
        #expect(throws: (any Error).self) { try Data([0x80]).sleb(&cursor) }
        cursor = 0
        #expect(try Data([0x7c]).sleb(&cursor) == -4)
    }
}
#endif
