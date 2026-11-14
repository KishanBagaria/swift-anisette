import Foundation
import CAnisette

final class GuestMachine {
    static let returnAddress: UInt64 = 0x100000000
    static let scratchBase: UInt64 = 0x300000000000
    static let scratchSize: UInt64 = 32 << 20
    static let heapBase: UInt64 = 0x400000000000
    static let heapSize: UInt64 = 64 << 20
    static let stackBase: UInt64 = 0x500000000000
    static let stackSize: UInt64 = 8 << 20
    static let stackEnd = stackBase + stackSize
    let engine: Unicorn
    let services: GuestServices
    private var scratchCursor: UInt64 = 0

    init(name: String, profile: Profile, library: UnicornLibrary,
         cancellation: Cancellation, pauseRunLoop: Bool = false) throws {
        engine = try Unicorn(library: library, cancellation: cancellation)
        for (address, size) in [(Self.returnAddress, UInt64(4096)), (Self.scratchBase, Self.scratchSize),
                                (Self.heapBase, Self.heapSize), (Self.stackBase, Self.stackSize)] {
            try engine.map(address, size)
        }
        try engine.write(Self.returnAddress, UInt32(0xd4200000))
        services = try GuestServices(engine: engine, profile: profile, pauseRunLoop: pauseRunLoop)
        for (table, functions) in [(profile.functions, true), (profile.slots, false)] {
            var mapped = Set<UInt64>()
            for (address, target) in table {
                for page in [address & ~UInt64(4095), try guestAddress(address, offset: functions ? 15 : 7) & ~UInt64(4095)] {
                    if mapped.insert(page).inserted { try engine.map(page, 4096) }
                }
                if functions {
                    try engine.write(address, Data.littleEndian(UInt32(0x58000050))
                        + Data.littleEndian(UInt32(0xd61f0200)) + Data.littleEndian(target))
                } else { try engine.write(address, target) }
            }
        }
        for image in profile.images where image.name == "CoreFP" || image.name == "AppleMediaServices" || image.name == name {
            try image.load(into: engine)
        }
    }

    func clearScratch() {
        if scratchCursor != 0 { try? engine.write(Self.scratchBase, Data(count: Int(scratchCursor))) }
        scratchCursor = 0
    }

    func scratch(_ data: Data = Data(), size: UInt64? = nil) throws -> UInt64 {
        let size = size ?? UInt64(data.count)
        try require(size <= Self.scratchSize && UInt64(data.count) <= size, "Invalid scratch allocation")
        let reserved = try guestAligned(max(size, 1))
        try require(scratchCursor <= Self.scratchSize - reserved, "Guest scratch area exhausted")
        let address = Self.scratchBase + scratchCursor
        scratchCursor += reserved
        try engine.write(address, data.isEmpty ? Data(count: Int(size)) : data)
        return address
    }

    @discardableResult
    func invoke(_ address: UInt64, _ arguments: UInt64...) throws -> UInt64 {
        try invoke(address, arguments: arguments)
    }

    @discardableResult
    func invoke(_ address: UInt64, arguments: [UInt64]) throws -> UInt64 {
        try require(address != 0, "Missing guest entry point")
        for index in 0..<8 { try engine.register(Unicorn.x0 + Int32(index), arguments.indices.contains(index) ? arguments[index] : 0) }
        let extra = max(arguments.count - 8, 0)
        let stack = (Self.stackEnd - UInt64(extra * 8)) & ~UInt64(15)
        for index in 0..<extra { try engine.write(stack + UInt64(index * 8), arguments[index + 8]) }
        try engine.register(Unicorn.sp, stack)
        try engine.register(Unicorn.lr, Self.returnAddress)
        services.fault = nil
        services.pausedAtRunLoop = false
        let deadline = ContinuousClock.now.advanced(by: .seconds(60))
        var next = address
        while true {
            try require(ContinuousClock.now < deadline, "Guest execution timed out")
            do {
                try engine.start(next, until: Self.returnAddress, timeout: 60_000_000)
                break
            } catch {
                if let fault = services.fault { throw fault }
                if error is CancellationError { throw error }
                guard try emulateUnsupportedInstruction() else {
                    let pc = try engine.register(Unicorn.pc)
                    let lr = try engine.register(Unicorn.lr)
                    throw AnisetteError("Guest failed at 0x\(String(pc, radix: 16)) (LR 0x\(String(lr, radix: 16))): \(error)")
                }
                next = try engine.register(Unicorn.pc)
            }
        }
        if let fault = services.fault { throw fault }
        let pc = try engine.register(Unicorn.pc)
        try require(pc == Self.returnAddress || services.pausedAtRunLoop, "Guest stopped before returning")
        return try engine.register(Unicorn.x0)
    }

    private func generalRegister(_ index: UInt32) -> Int32 {
        switch index {
        case 29: 1
        case 30: Unicorn.lr
        default: Unicorn.x0 + Int32(index)
        }
    }

    private func emulateUnsupportedInstruction() throws -> Bool {
        let pc = try engine.register(Unicorn.pc)
        guard let instruction = try? engine.read(pc, as: UInt32.self) else { return false }
        if instruction & 0xffe08000 == 0xce000000 {
            let first = try engine.vector(228 + Int32((instruction >> 5) & 31))
            let second = try engine.vector(228 + Int32((instruction >> 16) & 31))
            let third = try engine.vector(228 + Int32((instruction >> 10) & 31))
            let result = Data((0..<16).map { first[$0] ^ second[$0] ^ third[$0] })
            try engine.vector(228 + Int32(instruction & 31), result)
        } else {
            let opcode = instruction & 0xffe0fc00
            guard [0x88e0fc00, 0xc8e0fc00, 0xb8e08000, 0xf8e08000].contains(opcode) else { return false }
            let width: UInt64 = opcode == 0x88e0fc00 || opcode == 0xb8e08000 ? 4 : 8
            let source = (instruction >> 16) & 31
            let base = (instruction >> 5) & 31
            let destination = instruction & 31
            let address = try engine.register(base == 31 ? Unicorn.sp : generalRegister(base))
            var bytes = try engine.read(address, width)
            bytes.append(Data(count: 8 - Int(width)))
            let old: UInt64 = try bytes.integer(at: 0)
            let mask: UInt64 = width == 4 ? 0xffffffff : .max
            let value = try source == 31 ? 0 : engine.register(generalRegister(source)) & mask
            if opcode == 0x88e0fc00 || opcode == 0xc8e0fc00 {
                if old == value {
                    let replacement = try destination == 31 ? 0 : engine.register(generalRegister(destination)) & mask
                    try engine.write(address, Data(Data.littleEndian(replacement).prefix(Int(width))))
                }
                if source != 31 { try engine.register(generalRegister(source), old) }
            } else {
                try engine.write(address, Data(Data.littleEndian(value).prefix(Int(width))))
                if destination != 31 { try engine.register(generalRegister(destination), old) }
            }
        }
        try engine.register(Unicorn.pc, guestAddress(pc, offset: 4))
        return true
    }
}
