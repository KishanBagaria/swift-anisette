import Foundation
import CAnisette

/// Every failure the library reports itself. Task cancellation surfaces as `CancellationError`.
public struct AnisetteError: Error, LocalizedError, CustomStringConvertible, Equatable, Hashable, Sendable {
    /// ADI's "not provisioned" status: provision the identity, then retry.
    public static let notProvisionedStatus: Int32 = -45061

    /// A human-readable description of the failure.
    public let description: String
    /// The status Apple's ADI returned, when the failure came from ADI itself.
    public let adiStatus: Int32?

    /// A localized message describing the failure, matching `description`.
    public var errorDescription: String? { description }

    init(_ description: String, adiStatus: Int32? = nil) {
        self.description = description
        self.adiStatus = adiStatus
    }
}

func require(_ condition: Bool, _ message: String) throws {
    guard condition else { throw AnisetteError(message) }
}

func guestAddress(_ base: UInt64, offset: UInt64) throws -> UInt64 {
    let (address, overflow) = base.addingReportingOverflow(offset)
    try require(!overflow, "Guest address overflow")
    return address
}

func guestAligned(_ value: UInt64, to alignment: UInt64 = 16) throws -> UInt64 {
    try require(alignment > 0 && alignment & (alignment - 1) == 0, "Invalid guest alignment")
    return try guestAddress(value, offset: alignment - 1) & ~(alignment - 1)
}

extension Data {
    func lzfseDecoded(size: Int, lzvn: Bool = false) throws -> Data {
        try require(size > 0 && size <= 256 << 20, "Invalid LZFSE output size")
        // One spare byte distinguishes a complete decode from the API's
        // successful-looking partial output when the destination fills up.
        var output = Data(count: size + 1)
        let decodedSize = output.withUnsafeMutableBytes { dst in
            withUnsafeBytes { src in anisette_lzfse_decode(src.baseAddress, src.count, dst.baseAddress, dst.count, lzvn) }
        }
        try require(decodedSize == size, "Invalid LZFSE/LZVN data")
        output.removeLast()
        return output
    }

    /// Inflates a raw DEFLATE stream (no zlib header), as stored in ZIP members.
    func inflated(size: Int) throws -> Data {
        try require(size > 0 && size <= 256 << 20, "Invalid decompression size")
        var output = Data(count: size)
        var length = size
        let code = output.withUnsafeMutableBytes { dst in
            withUnsafeBytes { src in anisette_inflate(src.baseAddress, src.count, dst.baseAddress, &length) }
        }
        try require(code == 0 && length == size, "Invalid compressed data")
        return output
    }

    var crc32: UInt32 {
        precondition(count <= 256 << 20)
        return withUnsafeBytes { anisette_crc32($0.baseAddress, $0.count) }
    }

    func integer<T: FixedWidthInteger>(at offset: Int, as type: T.Type = T.self) throws -> T {
        try require(offset >= 0 && offset <= count && MemoryLayout<T>.size <= count - offset, "Truncated binary field")
        return withUnsafeBytes { T(littleEndian: $0.loadUnaligned(fromByteOffset: offset, as: T.self)) }
    }

    mutating func put<T: FixedWidthInteger>(_ value: T, at offset: Int) throws {
        try require(offset >= 0 && offset <= count && MemoryLayout<T>.size <= count - offset, "Binary write outside buffer")
        var value = value.littleEndian
        Swift.withUnsafeBytes(of: &value) { bytes in replaceSubrange(offset..<offset + bytes.count, with: bytes) }
    }

    static func littleEndian<T: FixedWidthInteger>(_ value: T) -> Data {
        var value = value.littleEndian
        return Swift.withUnsafeBytes(of: &value) { Data($0) }
    }
}
