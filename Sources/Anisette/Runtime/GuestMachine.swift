import Foundation

final class GuestMachine {
    static let returnAddress: UInt64 = 0x100000000
    static let scratchBase: UInt64 = 0x300000000000
    static let scratchSize: UInt64 = 32 << 20
    static let heapBase: UInt64 = 0x400000000000
    static let heapSize: UInt64 = 64 << 20
    static let stackBase: UInt64 = 0x500000000000
    static let stackSize: UInt64 = 8 << 20
    static let stackEnd = stackBase + stackSize
    let engine: any GuestEngine
    let services: GuestServices
    private var scratchCursor: UInt64 = 0

    static func requiredImages(for name: String) -> Set<String> {
        switch name {
        case "commerce": [name, "CoreFP", "AppleMediaServices"]
        default: [name]
        }
    }

    init(name: String, profile: Profile, engine: any GuestEngine, pauseRunLoop: Bool = false) throws {
        self.engine = engine
        for (address, size) in [(Self.returnAddress, UInt64(4096)), (Self.scratchBase, Self.scratchSize),
                                (Self.heapBase, Self.heapSize), (Self.stackBase, Self.stackSize)] {
            try engine.map(address, size)
        }
        try engine.writeReturnTrap(at: Self.returnAddress)
        services = try GuestServices(engine: engine, profile: profile, pauseRunLoop: pauseRunLoop)
        let required = Self.requiredImages(for: name)
        if required.contains("AppleMediaServices") {
            try mapSharedCacheTables(from: profile)
        }
        for image in profile.images where required.contains(image.name) {
            try image.load(into: engine)
        }
    }

    private func mapSharedCacheTables(from profile: Profile) throws {
        var mapped = Set<UInt64>()
        for (table, functions) in [(profile.functions, true), (profile.slots, false)] {
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
        for index in 0..<8 { try engine.register(.x(index), arguments.indices.contains(index) ? arguments[index] : 0) }
        let extra = max(arguments.count - 8, 0)
        let stack = (Self.stackEnd - UInt64(extra * 8)) & ~UInt64(15)
        for index in 0..<extra { try engine.write(stack + UInt64(index * 8), arguments[index + 8]) }
        try engine.register(.sp, stack)
        try engine.register(.lr, Self.returnAddress)
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
                guard engine.emulatesUnsupportedInstructions, try emulateUnsupportedInstruction() else {
                    let pc = try engine.register(.pc)
                    let lr = try engine.register(.lr)
                    throw AnisetteError("Guest failed at 0x\(String(pc, radix: 16)) (LR 0x\(String(lr, radix: 16))): \(error). "
                        + "Retrying will not help; report this with the build \(try PinnedBuild.current().cacheName) "
                        + "at https://github.com/KishanBagaria/swift-anisette/issues")
                }
                next = try engine.register(.pc)
            }
        }
        if let fault = services.fault { throw fault }
        let pc = try engine.register(.pc)
        try require(pc == Self.returnAddress || services.pausedAtRunLoop, "Guest stopped before returning")
        return try engine.register(.x0)
    }

    private func readGeneral(_ index: UInt32, mask: UInt64 = .max) throws -> UInt64 {
        index == 31 ? 0 : try engine.register(.x(Int(index))) & mask
    }

    private func writeAtomic(_ value: UInt64, to address: UInt64, width: UInt64) throws {
        if width == 4 { try engine.write(address, UInt32(truncatingIfNeeded: value)) } else { try engine.write(address, value) }
    }

    func emulateUnsupportedInstruction() throws -> Bool {
        let pc = try engine.register(.pc)
        guard let instruction = try? engine.read(pc, as: UInt32.self) else { return false }
        // EOR3 Vd.16B, Vn.16B, Vm.16B, Va.16B (ARMv8.2 SHA3): 11001110_000_Rm_0_Ra_Rn_Rd
        if instruction & 0xffe08000 == 0xce000000 {
            let first = try engine.vector(Int((instruction >> 5) & 31))
            let second = try engine.vector(Int((instruction >> 16) & 31))
            let third = try engine.vector(Int((instruction >> 10) & 31))
            let result = Data((0..<16).map { first[$0] ^ second[$0] ^ third[$0] })
            try engine.vector(Int(instruction & 31), result)
        } else if try !emulateAtomic(instruction) {
            return false
        }
        try engine.register(.pc, guestAddress(pc, offset: 4))
        return true
    }

    private func emulateAtomic(_ instruction: UInt32) throws -> Bool {
        // ARMv8.1 LSE CAS/CASA/CASL/CASAL (32/64-bit): 1x_0010001_L_1_Rs_o0_11111_Rn_Rt
        let isCAS = instruction & 0xbfa07c00 == 0x88a07c00
        // ARMv8.1 LSE SWP/SWPA/SWPL/SWPAL (32/64-bit): 1x_111000_A_R_1_Rs_100000_Rn_Rt
        let isSWP = instruction & 0xbf20fc00 == 0xb8208000
        guard isCAS || isSWP else { return false }
        let width: UInt64 = instruction & 0x40000000 == 0 ? 4 : 8
        let mask: UInt64 = width == 4 ? 0xffffffff : .max
        let source = (instruction >> 16) & 31
        let base = (instruction >> 5) & 31
        let destination = instruction & 31
        let address = try engine.register(base == 31 ? .sp : .x(Int(base)))
        let old = try width == 4 ? UInt64(engine.read(address, as: UInt32.self)) : engine.read(address, as: UInt64.self)
        let value = try readGeneral(source, mask: mask)
        if isCAS {
            if old == value {
                try writeAtomic(readGeneral(destination, mask: mask), to: address, width: width)
            }
            if source != 31 { try engine.register(.x(Int(source)), old) }
        } else {
            try writeAtomic(value, to: address, width: width)
            if destination != 31 { try engine.register(.x(Int(destination)), old) }
        }
        return true
    }
}
