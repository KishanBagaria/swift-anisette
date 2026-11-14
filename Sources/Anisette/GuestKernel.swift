import Foundation
import Crypto
import CryptoExtras

extension GuestServices {
    // swiftlint:disable cyclomatic_complexity
    func kernelService(_ name: String) throws -> Bool {
        switch name {
        case "ioConnectCallStructMethod": try ioConnect()
        case "waitForKernelService":
            guard try string(argument(0)) == "IOAESAccelerator" else { try result(0); return true }
            if aesService == 0 {
                let unhandled = try addFunction("$IOAES.unhandled", handler: "returnZero")
                let retain = try addFunction("$IOAES.retain", handler: "returnUnchanged")
                let perform = try addFunction("$IOAES.perform", handler: "ioAESPerform")
                var vtable = Data()
                for _ in 0..<0x120 { vtable.append(.littleEndian(unhandled)) }
                try vtable.put(retain, at: 0x20)
                try vtable.put(perform, at: 0x550)
                try vtable.put(perform, at: 0x890)
                let table = try addData("kernel.ioaes.vtable", vtable)
                aesService = try allocate(16)
                try engine.write(aesService, table)
            }
            try result(aesService)
        case "newKernelBufferDescriptor", "newKernelBufferDescriptorAt":
            let capacity = try argument(name == "newKernelBufferDescriptor" ? 2 : 1)
            guard capacity > 0 && capacity <= 64 << 20 else { try result(0); return true }
            let address: UInt64
            if name == "newKernelBufferDescriptor" {
                address = try allocate(capacity)
                try engine.write(address, Data(count: Int(capacity)))
            } else { address = try argument(0) }
            try createKernelBuffer(address, capacity: capacity)
        case "kernelBufferPrepare", "kernelBufferAddress", "kernelBufferRead", "kernelBufferWrite":
            let descriptor = try argument(0)
            let buffer = try engine.read(guestAddress(descriptor, offset: 8), as: UInt64.self)
            let capacity = try engine.read(guestAddress(descriptor, offset: 16), as: UInt64.self)
            switch name {
            case "kernelBufferPrepare": try result(buffer == 0 || capacity == 0 || capacity > 64 << 20 ? 3 : 0)
            case "kernelBufferAddress": try result(buffer)
            default:
                let offset = try argument(1), address = try argument(2), length = try argument(3)
                guard offset <= capacity && length <= capacity - offset && length <= 64 << 20 else {
                    try result(0); return true
                }
                let bufferOffset = try guestAddress(buffer, offset: offset)
                let source = name == "kernelBufferRead" ? bufferOffset : address
                let destination = name == "kernelBufferRead" ? address : bufferOffset
                try engine.write(destination, engine.read(source, length)); try result(length)
            }
        case "ioAESPerform": try performAES()
        case "unsupportedKernelBufferMethod": throw AnisetteError("Unsupported kernel buffer method")
        default: return false
        }
        return true
    }
    // swiftlint:enable cyclomatic_complexity

    private func createKernelBuffer(_ address: UInt64, capacity: UInt64) throws {
        if bufferVtable == 0 {
            let unhandled = try addFunction("$IOBuffer.unhandled", handler: "unsupportedKernelBufferMethod")
            let prepare = try addFunction("$IOBuffer.prepare", handler: "kernelBufferPrepare")
            let complete = try addFunction("$IOBuffer.complete", handler: "returnZero")
            let getAddress = try addFunction("$IOBuffer.address", handler: "kernelBufferAddress")
            let read = try addFunction("$IOBuffer.read", handler: "kernelBufferRead")
            let write = try addFunction("$IOBuffer.write", handler: "kernelBufferWrite")
            var table = Data()
            for _ in 0..<0x200 { table.append(.littleEndian(unhandled)) }
            for (offset, value) in [(0x28, complete), (0xc8, read), (0xd0, write), (0xd8, prepare),
                                    (0xe0, complete), (0x148, getAddress), (0x218, prepare), (0x220, complete), (0x308, getAddress)] {
                try table.put(value, at: offset)
            }
            bufferVtable = try addData("kernel.buffer.vtable", table)
        }
        let descriptor = try allocate(24)
        try engine.write(descriptor, bufferVtable)
        try engine.write(guestAddress(descriptor, offset: 8), address)
        try engine.write(guestAddress(descriptor, offset: 16), capacity)
        try result(descriptor)
    }

    private func performAES() throws {
        let arguments = try (0..<9).map { try argument($0) }
        let length = arguments[3]
        guard length > 0 && length <= 64 << 20 && length % 16 == 0 else { try result(3); return }
        let sourceBase = try engine.read(guestAddress(arguments[1], offset: 8), as: UInt64.self)
        let sourceCapacity = try engine.read(guestAddress(arguments[1], offset: 16), as: UInt64.self)
        let destinationBase = try engine.read(guestAddress(arguments[2], offset: 8), as: UInt64.self)
        let destinationCapacity = try engine.read(guestAddress(arguments[2], offset: 16), as: UInt64.self)
        guard arguments[7] <= sourceCapacity && length <= sourceCapacity - arguments[7]
                && arguments[8] <= destinationCapacity && length <= destinationCapacity - arguments[8] else {
            try result(3); return
        }
        let source = try engine.read(guestAddress(sourceBase, offset: arguments[7]), length)
        let iv = try engine.read(arguments[4], 16)
        let keyData = try engine.read(arguments[6], 40)
        let (destination, nextIV) = try Self.ioAES(source, iv: iv,
                                                   operation: UInt32(truncatingIfNeeded: arguments[5]), keyData: keyData)
        try engine.write(guestAddress(destinationBase, offset: arguments[8]), destination)
        try engine.write(arguments[4], nextIV)
        try result(0)
    }

    static func ioAES(_ source: Data, iv: Data, operation: UInt32, keyData: Data) throws -> (Data, Data) {
        try require(!source.isEmpty && source.count % 16 == 0 && iv.count == 16 && keyData.count == 40,
                    "Invalid IOAES parameters")
        let handle: UInt32 = try keyData.integer(at: 36)
        try require(handle == 0x89c, "Unsupported IOAES key handle")
        let key = SymmetricKey(data: Data(count: 16))
        let initializationVector = try AES._CBC.IV(ivBytes: iv)
        switch operation {
        case 0:
            let output = try AES._CBC.encrypt(source, using: key, iv: initializationVector, noPadding: true)
            return (output, Data(output.suffix(16)))
        case 1:
            return (try AES._CBC.decrypt(source, using: key, iv: initializationVector, noPadding: true), Data(source.suffix(16)))
        default: throw AnisetteError("Unsupported IOAES operation")
        }
    }

    private func ioConnect() throws {
        let selector = try argument(1), count = try argument(3), sizeAddress = try argument(5)
        let capacity: UInt64 = try sizeAddress == 0 ? 0 : engine.read(sizeAddress, as: UInt64.self)
        try require(count <= 1 << 20 && capacity <= 1 << 20, "IOKit buffer exceeds limit")
        let input = try engine.read(argument(2), count)
        var indirect = Data()
        var indirectAddress: UInt64 = 0
        if selector == 26 && input.count == 16 {
            indirectAddress = try input.integer(at: 0)
            let length: UInt64 = try input.integer(at: 8)
            try require(length > 0 && length <= 1 << 20, "Invalid indirect IOKit buffer")
            indirect = try engine.read(indirectAddress, length)
        }
        guard let fairPlayHandler else { throw AnisetteError("Missing virtual FairPlay service") }
        var output = Data(input.prefix(Int(capacity)))
        var (updated, status) = try fairPlayHandler(indirect)
        if status != 0 && selector == 26 && indirect.count >= 16 && input.count == capacity {
            updated = indirect
            let digest = Data(SHA256.hash(data: indirect.dropLast(16)).prefix(16))
            updated.replaceSubrange(updated.count - 16..<updated.count, with: digest)
            output = input; status = 0
        }
        if !updated.isEmpty {
            try require(updated.count <= indirect.count, "FairPlay response exceeds indirect buffer")
            try engine.write(indirectAddress, updated)
            if output.count >= 8 { try output.put(indirectAddress, at: 0) }
        }
        try require(output.count <= capacity, "FairPlay response exceeds output buffer")
        try engine.write(argument(4), output)
        if sizeAddress != 0 { try engine.write(sizeAddress, UInt64(output.count)) }
        try result(UInt64(UInt32(bitPattern: status)))
    }
}
