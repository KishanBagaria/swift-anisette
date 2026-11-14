import Foundation
import Crypto
import CryptoExtras

/// AEA symmetric-profile reader for public restore images.
/// Authentication covers every header and segment before its plaintext is used.
final class AEAFile {
    struct Segment {
        let offset: UInt64
        let compressed: Int
        let size: Int
        let checksum: Data
        let mac: Data
        let cluster: UInt32
        let index: UInt32
    }
    let source: AssetFile
    let size: UInt64
    let segmentSize: Int
    let mainKey: Data
    let segments: [Segment]
    private let cache = AssetDataCache(maximum: 64 << 20)

    private init(source: AssetFile, size: UInt64, segmentSize: Int, mainKey: Data, segments: [Segment]) {
        self.source = source; self.size = size; self.segmentSize = segmentSize
        self.mainKey = mainKey; self.segments = segments
    }

    static func open(_ source: AssetFile, http: AnisetteHTTPClient) async throws -> AEAFile {
        let header = try await source.read(0, 12)
        let profile: UInt32 = try header.integer(at: 4)
        let authSize = Int(try header.integer(at: 8, as: UInt32.self))
        try require(header.prefix(4) == Data("AEA1".utf8) && profile & 0xffffff == 1 && authSize <= 1 << 20,
                    "Unsupported AEA header")
        let auth = try await source.read(12, authSize)
        let key = try await resolveKey(metadata(auth), http: http)
        let salt = try await source.read(UInt64(12 + authSize), 32)
        let mainKey = derive(key, salt: salt, info: Data("AEA_AMK".utf8) + .littleEndian(profile), size: key.count)
        let rootOffset = UInt64(44 + authSize)
        let encrypted = try await source.read(rootOffset, 112)
        let rootKey = derive(mainKey, info: Data("AEA_RHEK".utf8), size: 80)
        let rootData = try encrypted.bytes(at: 32, size: 48)
        let clusterMAC = try encrypted.bytes(at: 80, size: 32)
        try authenticate(rootKey, data: rootData, salt: clusterMAC + auth, expected: Data(encrypted.prefix(32)))
        let root = try decrypt(rootData, key: rootKey)
        let size: UInt64 = try root.integer(at: 0)
        let segmentSize = Int(try root.integer(at: 16, as: UInt32.self))
        let clusterCount = Int(try root.integer(at: 20, as: UInt32.self))
        try require(try root.integer(at: 8, as: UInt64.self) == source.size && size > 0 && size <= 64 << 30,
                    "AEA image size does not match pinned archive")
        try require(segmentSize > 0 && segmentSize <= 16 << 20 && clusterCount > 0 && clusterCount <= 16384
            && root[24] == 0x65 && root[25] == 2, "Unsupported AEA segment encoding")
        let segments = try await index(source, rootOffset: rootOffset + 112, size: size,
                                       segmentSize: segmentSize, clusterCount: clusterCount, key: mainKey, mac: clusterMAC)
        return AEAFile(source: source, size: size, segmentSize: segmentSize, mainKey: mainKey, segments: segments)
    }

    static func metadata(_ data: Data) throws -> [String: Data] {
        var offset = 0, result: [String: Data] = [:]
        while offset < data.count {
            let length = Int(try data.integer(at: offset, as: UInt32.self))
            try require(length >= 5 && length <= data.count - offset, "Invalid AEA metadata length")
            let record = try data.bytes(at: offset + 4, size: length - 4)
            guard let end = record.firstIndex(of: 0), end > 0 else { throw AnisetteError("Invalid AEA metadata key") }
            let name = String(decoding: record.prefix(end), as: UTF8.self)
            try require(result[name] == nil, "Duplicate AEA metadata key")
            result[name] = Data(record.dropFirst(end + 1)); offset += length
        }
        return result
    }

    private static func resolveKey(_ metadata: [String: Data], http: AnisetteHTTPClient) async throws -> Data {
        guard let urlData = metadata["com.apple.wkms.fcs-key-url"],
              let url = URL(string: String(decoding: urlData, as: UTF8.self)), url.scheme == "https",
              url.host == "wkms-public.apple.com", url.user == nil, url.password == nil,
              url.port == nil || url.port == 443,
              let response = metadata["com.apple.wkms.fcs-response"] else { throw AnisetteError("Invalid Apple FCS metadata") }
        let pem = try await http.fetch(url, nil)
        try require(pem.count <= 64 << 10, "Apple FCS key exceeds limit")
        let privateKey = try P256.KeyAgreement.PrivateKey(pemRepresentation: String(decoding: pem, as: UTF8.self))
        let wrapped = try JSONDecoder().decode([String: String].self, from: response)
        guard let enc = wrapped["enc-request"].flatMap({ Data(base64Encoded: $0) }),
              let ciphertext = wrapped["wrapped-key"].flatMap({ Data(base64Encoded: $0) }) else {
            throw AnisetteError("Invalid Apple FCS wrapped key")
        }
        var recipient = try HPKE.Recipient(privateKey: privateKey, ciphersuite: .P256_SHA256_AES_GCM_256,
                                           info: Data(), encapsulatedKey: enc)
        let key = try recipient.open(ciphertext)
        try require(key.count == 32, "Invalid Apple FCS symmetric key size")
        return key
    }

    private static func index(_ source: AssetFile, rootOffset: UInt64, size: UInt64, segmentSize: Int,
                              clusterCount: Int, key: Data, mac: Data) async throws -> [Segment] {
        var offset = rootOffset, output: UInt64 = 0, expectedMAC = mac, cluster: UInt32 = 0
        var segments: [Segment] = []
        let expectedCount = (size + UInt64(segmentSize) - 1) / UInt64(segmentSize)
        try require(expectedCount <= 1 << 20, "AEA segment count exceeds limit")
        while output < size {
            let header = try await source.read(offset, clusterCount * 72 + 32)
            let clusterKey = derive(key, info: Data("AEA_CK".utf8) + .littleEndian(cluster), size: key.count)
            let headerKey = derive(clusterKey, info: Data("AEA_CHEK".utf8), size: 80)
            let encryptedSize = clusterCount * 40
            let encrypted = Data(header.prefix(encryptedSize))
            let nextMAC = try header.bytes(at: encryptedSize, size: 32)
            let macs = Data(header.dropFirst(encryptedSize + 32))
            try authenticate(headerKey, data: encrypted, salt: nextMAC + macs, expected: expectedMAC)
            let plain = try decrypt(encrypted, key: headerKey)
            offset += UInt64(header.count)
            for index in 0..<clusterCount {
                let length = Int(try plain.integer(at: index * 40, as: UInt32.self))
                let compressed = Int(try plain.integer(at: index * 40 + 4, as: UInt32.self))
                if length == 0 {
                    try require(compressed == 0 && output == size, "Missing AEA segment")
                    continue
                }
                try require(output < size, "AEA segment exceeds declared output")
                try require(length == min(segmentSize, Int(size - output)) && compressed > 0 && compressed <= segmentSize
                    && offset <= source.size && UInt64(compressed) <= source.size - offset,
                            "Invalid AEA segment layout")
                segments.append(.init(offset: offset, compressed: compressed, size: length,
                                      checksum: try plain.bytes(at: index * 40 + 8, size: 32),
                                      mac: try macs.bytes(at: index * 32, size: 32), cluster: cluster, index: UInt32(index)))
                offset += UInt64(compressed); output += UInt64(length)
            }
            expectedMAC = nextMAC; cluster += 1
        }
        try require(segments.count == expectedCount && offset <= source.size, "Incomplete AEA index")
        return segments
    }

    var file: AssetFile {
        AssetFile(size: size) { offset, count in
            var position = offset, result = Data()
            while result.count < count {
                let index = Int(position / UInt64(self.segmentSize))
                let bytes = try await self.decode(index)
                let inside = Int(position % UInt64(self.segmentSize))
                let length = min(count - result.count, bytes.count - inside)
                try require(length > 0, "Incomplete AEA segment")
                result.append(try bytes.bytes(at: inside, size: length)); position += UInt64(length)
            }
            return result
        }
    }

    private func decode(_ index: Int) async throws -> Data {
        if let data = cache[UInt64(index)] { return data }
        try require(segments.indices.contains(index), "Missing AEA segment")
        let segment = segments[index]
        let clusterKey = Self.derive(mainKey, info: Data("AEA_CK".utf8) + .littleEndian(segment.cluster), size: mainKey.count)
        let key = Self.derive(clusterKey, info: Data("AEA_SK".utf8) + .littleEndian(segment.index), size: 80)
        let encrypted = try await source.read(segment.offset, segment.compressed)
        try Self.authenticate(key, data: encrypted, expected: segment.mac)
        let compressed = try Self.decrypt(encrypted, key: key)
        let data = try segment.compressed == segment.size ? compressed : compressed.lzfseDecoded(size: segment.size)
        try require(Data(SHA256.hash(data: data)) == segment.checksum, "AEA segment checksum mismatch")
        cache[UInt64(index)] = data
        return data
    }

    static func derive(_ key: Data, salt: Data = Data(), info: Data, size: Int) -> Data {
        HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: key), salt: salt, info: info,
                               outputByteCount: size).withUnsafeBytes { Data($0) }
    }

    static func authenticate(_ key: Data, data: Data, salt: Data = Data(), expected: Data) throws {
        let message = salt + data + Data.littleEndian(UInt64(salt.count))
        let authenticationKey = SymmetricKey(data: key.prefix(32))
        let valid = HMAC<SHA256>.isValidAuthenticationCode(expected, authenticating: message, using: authenticationKey)
        try require(valid, "AEA authentication failed")
    }

    static func decrypt(_ data: Data, key: Data) throws -> Data {
        try AES._CTR.decrypt(data, using: SymmetricKey(data: key.bytes(at: 32, size: 32)),
                             nonce: .init(nonceBytes: key.bytes(at: 64, size: 16)))
    }
}
