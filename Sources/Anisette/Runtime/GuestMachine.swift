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
                guard engine.emulatesUnsupportedInstructions, (try? emulateUnsupportedInstruction()) == true else {
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

    private func readWidth(_ address: UInt64, width: UInt64) throws -> UInt64 {
        switch width {
        case 1: UInt64(try engine.read(address, as: UInt8.self))
        case 2: UInt64(try engine.read(address, as: UInt16.self))
        case 4: UInt64(try engine.read(address, as: UInt32.self))
        default: try engine.read(address, as: UInt64.self)
        }
    }

    private func writeWidth(_ value: UInt64, to address: UInt64, width: UInt64) throws {
        switch width {
        case 1: try engine.write(address, UInt8(truncatingIfNeeded: value))
        case 2: try engine.write(address, UInt16(truncatingIfNeeded: value))
        case 4: try engine.write(address, UInt32(truncatingIfNeeded: value))
        default: try engine.write(address, value)
        }
    }

    func emulateUnsupportedInstruction() throws -> Bool {
        let pc = try engine.register(.pc)
        guard let instruction = try? engine.read(pc, as: UInt32.self) else { return false }
        let handled = try emulateSHA3(instruction)
            || emulateAuthenticatedLoad(instruction)
            || emulateLoadAcquireRCpc(instruction)
            || emulateAtomic(instruction)
        guard handled else { return false }
        try engine.register(.pc, guestAddress(pc, offset: 4))
        return true
    }

    private func emulateSHA3(_ instruction: UInt32) throws -> Bool {
        // ARMv8.2 SHA3 EOR3 (0xce000000) / BCAX (0xce200000): 11001110_00x_Rm_0_Ra_Rn_Rd
        let isEOR3 = instruction & 0xffe08000 == 0xce000000
        let isBCAX = instruction & 0xffe08000 == 0xce200000
        guard isEOR3 || isBCAX else { return false }
        let first = try engine.vector(Int((instruction >> 5) & 31))
        let second = try engine.vector(Int((instruction >> 16) & 31))
        let third = try engine.vector(Int((instruction >> 10) & 31))
        let result = Data((0..<16).map { index in
            isEOR3 ? (first[index] ^ second[index] ^ third[index])
                : (first[index] ^ (second[index] & ~third[index]))
        })
        try engine.vector(Int(instruction & 31), result)
        return true
    }

    private func emulateAuthenticatedLoad(_ instruction: UInt32) throws -> Bool {
        // ARMv8.3 PAuth LDRAA/LDRAB: 11111000_M_S_1_imm9_W_1_Rn_Rt
        guard instruction & 0xff200400 == 0xf8200400 else { return false }
        let s = (instruction >> 22) & 1
        let imm9 = (instruction >> 12) & 0x1ff
        let signed10 = (Int64((s << 9) | imm9) << 54) >> 54
        let baseReg = Int((instruction >> 5) & 31)
        let dest = Int(instruction & 31)
        let base = try engine.register(baseReg == 31 ? .sp : .x(baseReg))
        let address = try addingSigned(base, signed10 * 8)
        let value = try engine.read(address, as: UInt64.self)
        if instruction & (1 << 11) != 0 {
            try engine.register(baseReg == 31 ? .sp : .x(baseReg), address)
        }
        if dest != 31 { try engine.register(.x(dest), value) }
        return true
    }

    private func emulateLoadAcquireRCpc(_ instruction: UInt32) throws -> Bool {
        // ARMv8.3 LRCPC LDAPRB/LDAPRH/LDAPR (32/64-bit): size_111000_10_1_11111_110000_Rn_Rt
        guard instruction & 0x3ffffc00 == 0x38bfc000 else { return false }
        let width = UInt64(1) << ((instruction >> 30) & 3)
        let baseReg = Int((instruction >> 5) & 31)
        let dest = Int(instruction & 31)
        let address = try engine.register(baseReg == 31 ? .sp : .x(baseReg))
        let value = try readWidth(address, width: width)
        if dest != 31 { try engine.register(.x(dest), value) }
        return true
    }

    private func emulateAtomic(_ instruction: UInt32) throws -> Bool {
        // ARMv8.1 LSE CAS/CASB/CASH: size_0010001_L_1_Rs_o0_11111_Rn_Rt
        let isCAS = instruction & 0x3fa07c00 == 0x08a07c00
        // ARMv8.1 LSE SWP/SWPB/SWPH: size_111000_A_R_1_Rs_100000_Rn_Rt
        let isSWP = instruction & 0x3f20fc00 == 0x38208000
        // ARMv8.1 LSE LDADD/LDCLR/LDEOR/LDSET/LDSMAX/LDSMIN/LDUMAX/LDUMIN (+ B/H and ST* aliases)
        let isLDOP = instruction & 0x3f208c00 == 0x38200000
        guard isCAS || isSWP || isLDOP else { return false }
        let width = UInt64(1) << ((instruction >> 30) & 3)
        let mask: UInt64 = width == 8 ? .max : (UInt64(1) << (width * 8)) - 1
        let source = (instruction >> 16) & 31
        let base = (instruction >> 5) & 31
        let destination = instruction & 31
        let address = try engine.register(base == 31 ? .sp : .x(Int(base)))
        let old = try readWidth(address, width: width)
        let value = try readGeneral(source, mask: mask)
        if isCAS {
            if old == value {
                try writeWidth(readGeneral(destination, mask: mask), to: address, width: width)
            }
            if source != 31 { try engine.register(.x(Int(source)), old) }
        } else {
            let updated = isSWP ? value : Self.atomicOp((instruction >> 12) & 7, old: old, value: value, width: width, mask: mask)
            try writeWidth(updated, to: address, width: width)
            if destination != 31 { try engine.register(.x(Int(destination)), old) }
        }
        return true
    }

    private static func atomicOp(_ opc: UInt32, old: UInt64, value: UInt64, width: UInt64, mask: UInt64) -> UInt64 {
        func signed(_ raw: UInt64) -> Int64 {
            let shift = 64 - Int(width * 8)
            return Int64(bitPattern: raw << shift) >> shift
        }
        switch opc {
        case 0: return (old &+ value) & mask
        case 1: return (old & ~value) & mask
        case 2: return (old ^ value) & mask
        case 3: return (old | value) & mask
        case 4: return signed(old) >= signed(value) ? old : value
        case 5: return signed(old) <= signed(value) ? old : value
        case 6: return max(old, value)
        default: return min(old, value)
        }
    }
}
