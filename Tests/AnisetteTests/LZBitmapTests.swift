#if os(macOS) || os(Linux)
import Foundation
import Testing
@testable import Anisette

struct LZBitmapTests {
    @Test func decodesUpstreamCompressedFixtureWithinCallerLimit() throws {
        // eafer/libzbitmap test/files/002-compressed, covered by LICENSE.lzbitmap.
        let stream = try #require(Data(base64Encoded:
            "WkJNCS0AAKAAABgAABgAABgAAGFhYWFhYWFheDXvNA8AAPEPAAAAAAAAAAAAAAAAAAYAAAAAAA=="))
        let expected = Data(repeating: 0x61, count: 158) + Data("xa".utf8)
        #expect(try LZBitmap.decode(stream, maximum: 160) == expected)
        #expect(try LZBitmap.decode(stream, maximum: 1024) == expected)
        #expect(throws: (any Error).self) { try LZBitmap.decode(stream, maximum: 159) }
        let sliced = (Data([9]) + stream).dropFirst()
        #expect(try LZBitmap.decode(sliced, maximum: 160) == expected)
    }

    @Test func rejectsMalformedChunksAndInvalidLimits() throws {
        let zeroLengthChunk = Data([0x5a, 0x42, 0x4d, 9, 0, 0, 0, 1, 0, 0])
        #expect(throws: (any Error).self) { try LZBitmap.decode(zeroLengthChunk, maximum: 1) }
        let empty = Data([0x5a, 0x42, 0x4d, 9, 6, 0, 0, 0, 0, 0])
        for limit in [-1, 0, (64 << 20) + 1] {
            #expect(throws: (any Error).self) { try LZBitmap.decode(empty, maximum: limit) }
        }
    }
}
#endif
