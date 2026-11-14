#if os(macOS) || os(Linux)
import Foundation
import Testing
@testable import Anisette

struct AssetExtractionTests {
    @Test func assetViewsEnforceBoundsAndExactReads() async throws {
        let file = AssetFile.memory(Data([0, 1, 2, 3, 4, 5]))
        let view = try file.section(2, 3)
        #expect(try await view.read(1, 2) == Data([3, 4]))
        let slice = AssetFile.memory(Data([9, 1, 2, 3]).dropFirst())
        #expect(try await slice.read(0, 2) == Data([1, 2]))
        await #expect(throws: (any Error).self) { try await view.read(2, 2) }
        await #expect(throws: (any Error).self) { try await view.read(UInt64.max, 1) }
        #expect(throws: (any Error).self) { try file.section(UInt64.max, 1) }
        let truncated = AssetFile(size: 10) { _, _ in Data() }
        await #expect(throws: (any Error).self) { try await truncated.read(0, 1) }
    }

    @Test func zipDiscoveryHandlesStoredDeflateAndZIP64() async throws {
        // Independent fixtures from Python's zipfile writer; forced ZIP64 local header.
        let fixtures = [
            "UEsDBBQAAAAAAAAAIVA0m8ISFAAAABQAAAADAAAAbGlibmF0aXZlIGxpYnJhcnkgYnl0ZXNQSwECFAMUAAAAAAAAACFQNJvCEhQAAAAU"
                + "AAAAAwAAAAAAAAAAAAAAgAEAAAAAbGliUEsFBgAAAAABAAEAMQAAADUAAAAAAA==",
            "UEsDBBQAAAAIAAAAIVA0m8ISFgAAABQAAAADAAAAbGliy0ssySxLVcjJTCpKLKpUSKosSS0GAFBLAQIUAxQAAAAIAAAAIVA0m8IS"
                + "FgAAABQAAAADAAAAAAAAAAAAAACAAQAAAABsaWJQSwUGAAAAAAEAAQAxAAAANwAAAAAA",
        ]
        for (index, fixture) in fixtures.enumerated() {
            let data = try #require(Data(base64Encoded: fixture))
            let archive = try await RestoreArchive.open(.memory(data))
            let file = try await archive.member("lib", compressed: index == 0 ? 20 : 22, size: 20)
            #expect(try await file.read(0, 20) == Data("native library bytes".utf8))
            await #expect(throws: (any Error).self) { _ = try await archive.member("lib", compressed: 20, size: 21) }
            await #expect(throws: (any Error).self) { _ = try await RestoreArchive.open(.memory(Data(data.dropLast()))) }
        }
        // A small archive with ZIP64 directory fields, locator and end record.
        let name = Data("member".utf8), payload = Data([1, 2, 3])
        var local = Data(count: 30)
        try local.put(UInt32(0x04034b50), at: 0); try local.put(UInt16(name.count), at: 26)
        var directory = Data(count: 46)
        try directory.put(UInt32(0x02014b50), at: 0)
        for offset in [20, 24, 42] { try directory.put(UInt32.max, at: offset) }
        try directory.put(UInt16(name.count), at: 28); try directory.put(UInt16(28), at: 30)
        directory += name + Data.littleEndian(UInt16(1)) + Data.littleEndian(UInt16(24))
            + Data.littleEndian(UInt64(3)) + Data.littleEndian(UInt64(3)) + Data.littleEndian(UInt64(0))
        let prefix = local + name + payload
        var record = Data(count: 56)
        try record.put(UInt32(0x06064b50), at: 0); try record.put(UInt64(44), at: 4)
        try record.put(UInt64(1), at: 24); try record.put(UInt64(1), at: 32)
        try record.put(UInt64(directory.count), at: 40); try record.put(UInt64(prefix.count), at: 48)
        var locator = Data(count: 20)
        try locator.put(UInt32(0x07064b50), at: 0)
        try locator.put(UInt64(prefix.count + directory.count), at: 8); try locator.put(UInt32(1), at: 16)
        var end = Data(count: 22)
        try end.put(UInt32(0x06054b50), at: 0); try end.put(UInt16.max, at: 10)
        try end.put(UInt32.max, at: 12); try end.put(UInt32.max, at: 16)
        let archive = try await RestoreArchive.open(.memory(prefix + directory + record + locator + end))
        let file = try await archive.member("member", compressed: 3, size: 3)
        #expect(try await file.read(0, 3) == payload)
    }

    @Test func universalBinarySelectionChecksArchitectureAndSliceBounds() async throws {
        var data = Data(count: 32)
        try data.put(UInt32(0xcafebabe).byteSwapped, at: 0)
        try data.put(UInt32(1).byteSwapped, at: 4)
        try data.put(UInt32(0x100000c).byteSwapped, at: 8)
        try data.put(UInt32(0x80000002).byteSwapped, at: 12)
        try data.put(UInt32(28).byteSwapped, at: 16)
        try data.put(UInt32(4).byteSwapped, at: 20)
        data.replaceSubrange(28..<32, with: Data([1, 2, 3, 4]))
        let selected = try await APFSFile.arm64e(.memory(data))
        #expect(try await selected.read(0, 4) == Data([1, 2, 3, 4]))
        await #expect(throws: (any Error).self) { _ = try await APFSFile.arm64e(.memory(Data(data.prefix(27)))) }
        try data.put(UInt32(5).byteSwapped, at: 20)
        await #expect(throws: (any Error).self) { _ = try await APFSFile.arm64e(.memory(data)) }
        try data.put(UInt32(4).byteSwapped, at: 20)
        try data.put(UInt32(0x1000007).byteSwapped, at: 8)
        await #expect(throws: (any Error).self) { _ = try await APFSFile.arm64e(.memory(data)) }
    }

    @Test func extentReadsCrossBoundariesAndRejectSparseFiles() async throws {
        var data = Data(count: 12288)
        data.replaceSubrange(4096..<8192, with: Data(repeating: 1, count: 4096))
        data.replaceSubrange(8192..<12288, with: Data(repeating: 2, count: 4096))
        let extents: [APFSFile.Extent] = [.init(logical: 0, physical: 2, length: 4096),
                                          .init(logical: 4096, physical: 1, length: 4096)]
        let file = try APFSFile.extentFile(.memory(data), extents: extents, size: 8192)
        #expect(try await file.read(4094, 4) == Data([2, 2, 1, 1]))
        #expect(throws: (any Error).self) {
            try APFSFile.extentFile(.memory(data), extents: [.init(logical: 1, physical: 1, length: 4096)], size: 4096)
        }
        #expect(throws: (any Error).self) {
            try APFSFile.extentFile(.memory(data), extents: [.init(logical: 0, physical: UInt64.max, length: 1)], size: 1)
        }
    }

    @Test func decmpfsSeeksAcrossBlocksAndChecksIndex() async throws {
        let first = Data([6]) + Data(repeating: 0x41, count: 65536)
        let second = Data([6, 0x42, 0x43])
        let index = Data.littleEndian(UInt32(12)) + Data.littleEndian(UInt32(12 + first.count))
            + Data.littleEndian(UInt32(12 + first.count + second.count))
        let reader = try await DecmpfsFile.open(.memory(index + first + second), size: 65538, method: 8)
        #expect(try await reader.file.read(65535, 3) == Data([0x41, 0x42, 0x43]))
        var corrupt = index + first + second
        try corrupt.put(UInt32(11), at: 0)
        await #expect(throws: (any Error).self) { _ = try await DecmpfsFile.open(.memory(corrupt), size: 65538, method: 8) }
    }

    @Test func apfsTreeRejectsMalformedRecordOffsets() throws {
        var data = Data(count: 4096)
        try data.put(UInt16(3), at: 32); try data.put(UInt32(1), at: 36)
        try data.put(UInt16(8), at: 42)
        try data.put(UInt16(8), at: 58); try data.put(UInt16(8), at: 60); try data.put(UInt16(8), at: 62)
        try data.put(UInt64(0x3000000000000002), at: 64)
        let node = try APFSTree.node(data)
        #expect(try node.records[0].object == 2)
        #expect(try node.records[0].kind == 3)
        try data.put(UInt16.max, at: 56)
        #expect(throws: (any Error).self) { try APFSTree.node(data) }
        #expect(!APFSTree.checksum(data))
    }

    @Test func aeaMetadataRejectsTruncationAndDuplicates() throws {
        let item = Data.littleEndian(UInt32(8)) + Data([0x6b, 0, 1, 2])
        #expect(try AEAFile.metadata(item)["k"] == Data([1, 2]))
        #expect(throws: (any Error).self) { try AEAFile.metadata(Data(item.dropLast())) }
        #expect(throws: (any Error).self) { try AEAFile.metadata(item + item) }
        #expect(throws: (any Error).self) { try AEAFile.metadata(Data.littleEndian(UInt32.max)) }
    }

    @Test func kernelEnvelopeSelectsKernelPayload() throws {
        let payload = Data([1, 2, 3])
        let contents = Data([0x16, 4]) + Data("IM4P".utf8) + Data([0x16, 4]) + Data("krnl".utf8)
            + Data([0x16, 0, 4, 3]) + payload
        let container = Data([0x30, UInt8(contents.count)]) + contents
        #expect(try KernelAsset.envelope(container).payload == payload)
        let optionalMetadata = Data([0x30, UInt8(contents.count + 2)]) + contents + Data([0x30, 0])
        #expect(try KernelAsset.envelope(optionalMetadata).payload == payload)
        var wrongType = container; wrongType[12] = 0x78
        #expect(throws: (any Error).self) { try KernelAsset.envelope(wrongType) }
    }
}
#endif
