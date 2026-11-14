import Foundation
import libzbitmap

enum LZBitmap {
    static func decode(_ source: Data, maximum: Int) throws -> Data {
        try require(maximum > 0 && maximum <= 64 << 20, "Invalid LZBITMAP output limit")
        // Decode once into the caller-approved capacity. Upstream's size-only
        // query does not validate the stream and can hang on malformed chunks.
        var output = Data(count: maximum)
        var length = 0
        let status = output.withUnsafeMutableBytes { destination in
            source.withUnsafeBytes { input in
                zbm_decompress(destination.baseAddress, destination.count, input.baseAddress, input.count, &length)
            }
        }
        try require(status == 0 && length >= 0 && length <= maximum, "Invalid LZBITMAP data (\(status))")
        output.removeSubrange(length..<output.count)
        return output
    }
}
