#if os(macOS) && arch(arm64)
import Foundation
import Darwin
import Hypervisor

private struct PageTable {
    let host: UnsafeMutableRawPointer
    let ipa: UInt64
}

private struct MappedRegion {
    let vaStart: UInt64
    let vaEnd: UInt64
    let hostBase: UnsafeMutableRawPointer
}

private struct RegisterSnapshot {
    var x = [UInt64](repeating: 0, count: 31)
    var q = [Data](repeating: Data(count: 16), count: 32)
    var spEL1: UInt64 = 0
    var spEL0: UInt64 = 0
    var pc: UInt64 = 0
    var cpsr: UInt64 = ARM64.cpsrEL1h
    var fpcr: UInt64 = 0
    var fpsr: UInt64 = 0
    var tpidrEL0: UInt64 = 0
    var tpidrROEL0: UInt64 = 0
    var tpidrEL1: UInt64 = 0
    var elrEL1: UInt64 = 0
    var esrEL1: UInt64 = 0
    var farEL1: UInt64 = 0
    var spsrEL1: UInt64 = 0
    var contextidrEL1: UInt64 = 0
}

/// Manages 16 KiB-aligned IPA slabs and 4-level 4 KiB Stage-1 page tables for one guest machine.
private final class GuestAddressSpace {
    let runtime: HypervisorRuntime
    private var slabs: [Slab] = []
    private var freeSubPages: [PageTable] = []
    private var regions: [MappedRegion] = []
    private var tablesByIPA: [UInt64: UnsafeMutableRawPointer] = [:]
    let l0Table: PageTable

    init(runtime: HypervisorRuntime) throws {
        self.runtime = runtime
        let slab = try runtime.allocateSlab(size: Int(ARM64.ipaSlabSize))
        slabs.append(slab)
        freeSubPages += Self.pages(in: slab, from: 1).reversed()
        l0Table = PageTable(host: slab.host, ipa: slab.ipa)
        tablesByIPA[l0Table.ipa] = l0Table.host
        do { try installVectorTable() } catch { reclaim(); throw error }
    }

    func reclaim() {
        slabs.forEach(runtime.releaseSlab)
        slabs.removeAll()
        freeSubPages.removeAll()
        regions.removeAll()
        tablesByIPA.removeAll()
    }

    private static func pages(in slab: Slab, from first: Int) -> [PageTable] {
        (first..<slab.size / Int(ARM64.guestPageSize)).map { index in
            let offset = index * Int(ARM64.guestPageSize)
            return PageTable(host: slab.host.advanced(by: offset), ipa: slab.ipa + UInt64(offset))
        }
    }

    private func allocateSubPage() throws -> PageTable {
        if let reused = freeSubPages.popLast() { return reused }
        let slab = try runtime.allocateSlab(size: Int(ARM64.ipaSlabSize))
        slabs.append(slab)
        freeSubPages += Self.pages(in: slab, from: 1).reversed()
        return PageTable(host: slab.host, ipa: slab.ipa)
    }

    private func installVectorTable() throws {
        let vbarPage = try allocateSubPage()
        for offset in stride(from: 0, to: 2048, by: 4) {
            vbarPage.host.storeBytes(of: ARM64.hvcFFFF.littleEndian, toByteOffset: offset, as: UInt32.self)
        }
        sys_icache_invalidate(vbarPage.host, Int(ARM64.guestPageSize))
        try mapPage(va: ARM64.vbarGuestVA, ipa: vbarPage.ipa, descriptorBits: ARM64.roPageDescriptorBits)
    }

    private func ensureChildTable(in parent: PageTable, index: Int) throws -> PageTable {
        let entryOffset = index * 8
        let current = UInt64(littleEndian: parent.host.load(fromByteOffset: entryOffset, as: UInt64.self))
        if current & 0x3 == 0x3 {
            let nextIPA = current & 0x0000_ffff_ffff_f000
            guard let nextHost = tablesByIPA[nextIPA] else {
                throw AnisetteError("Missing Hypervisor page table at 0x\(String(nextIPA, radix: 16))")
            }
            return PageTable(host: nextHost, ipa: nextIPA)
        }
        let next = try allocateSubPage()
        tablesByIPA[next.ipa] = next.host
        let descriptor = (next.ipa & 0x0000_ffff_ffff_f000) | ARM64.tableDescriptorBits
        parent.host.storeBytes(of: descriptor.littleEndian, toByteOffset: entryOffset, as: UInt64.self)
        return next
    }

    private func ensureL3Table(for va: UInt64) throws -> PageTable {
        let l1 = try ensureChildTable(in: l0Table, index: Int((va >> 39) & 0x1ff))
        let l2 = try ensureChildTable(in: l1, index: Int((va >> 30) & 0x1ff))
        return try ensureChildTable(in: l2, index: Int((va >> 21) & 0x1ff))
    }

    private func mapPage(va: UInt64, ipa: UInt64, descriptorBits: UInt64) throws {
        let l3 = try ensureL3Table(for: va)
        let l3Offset = Int((va >> 12) & 0x1ff) * 8
        let leaf = (ipa & 0x0000_ffff_ffff_f000) | descriptorBits
        l3.host.storeBytes(of: leaf.littleEndian, toByteOffset: l3Offset, as: UInt64.self)
    }

    private func mapContiguousPages(vaStart: UInt64, ipaStart: UInt64, pageCount: Int, descriptorBits: UInt64) throws {
        var remaining = pageCount
        var va = vaStart
        var ipa = ipaStart
        while remaining > 0 {
            let l3 = try ensureL3Table(for: va)
            let startIndex = Int((va >> 12) & 0x1ff)
            let chunk = min(remaining, 512 - startIndex)
            let entries = l3.host.bindMemory(to: UInt64.self, capacity: 512)
            for offset in 0..<chunk {
                let leaf = (ipa & 0x0000_ffff_ffff_f000) | descriptorBits
                entries[startIndex + offset] = leaf.littleEndian
                ipa += ARM64.guestPageSize
            }
            va += UInt64(chunk) * ARM64.guestPageSize
            remaining -= chunk
        }
    }

    /// Index of the first region ending after `address`; regions are sorted and disjoint.
    private func firstRegionIndex(endingAfter address: UInt64) -> Int {
        var low = 0, high = regions.count
        while low < high {
            let middle = (low + high) / 2
            if regions[middle].vaEnd <= address { low = middle + 1 } else { high = middle }
        }
        return low
    }

    private func insertRegion(vaStart: UInt64, vaEnd: UInt64, hostBase: UnsafeMutableRawPointer) {
        regions.insert(MappedRegion(vaStart: vaStart, vaEnd: vaEnd, hostBase: hostBase),
                       at: firstRegionIndex(endingAfter: vaStart))
    }

    private func findRegion(containing address: UInt64) -> MappedRegion? {
        var low = 0, high = regions.count
        while low < high {
            let middle = (low + high) / 2
            let region = regions[middle]
            if address < region.vaStart {
                high = middle
            } else if address >= region.vaEnd {
                low = middle + 1
            } else {
                return region
            }
        }
        return nil
    }

    func map(_ address: UInt64, _ size: UInt64) throws {
        let vaEnd = address + size
        let next = firstRegionIndex(endingAfter: address)
        if next < regions.count, regions[next].vaStart < vaEnd {
            let page = max(address, regions[next].vaStart)
            throw AnisetteError("Guest page 0x\(String(page, radix: 16)) is already mapped")
        }
        if size < ARM64.ipaSlabSize {
            for page in stride(from: address, to: vaEnd, by: Int(ARM64.guestPageSize)) {
                let subPage = try allocateSubPage()
                try mapPage(va: page, ipa: subPage.ipa, descriptorBits: ARM64.rwPageDescriptorBits)
                insertRegion(vaStart: page, vaEnd: page + ARM64.guestPageSize, hostBase: subPage.host)
            }
            return
        }
        let slab = try runtime.allocateSlab(size: Int(try guestAligned(size, to: ARM64.ipaSlabSize)))
        slabs.append(slab)
        let pageCount = Int(size / ARM64.guestPageSize)
        try mapContiguousPages(
            vaStart: address,
            ipaStart: slab.ipa,
            pageCount: pageCount,
            descriptorBits: ARM64.rwPageDescriptorBits
        )
        insertRegion(vaStart: address, vaEnd: vaEnd, hostBase: slab.host)
        freeSubPages += Self.pages(in: slab, from: pageCount)
    }

    func resolvePages(for address: UInt64, count: UInt64) throws -> [(host: UnsafeMutableRawPointer, count: Int)] {
        let end = try guestAddress(address, offset: count - 1)
        var segments: [(host: UnsafeMutableRawPointer, count: Int)] = []
        var cursor = address
        while cursor <= end {
            guard let region = findRegion(containing: cursor) else {
                throw AnisetteError("Unmapped guest memory access at 0x\(String(cursor, radix: 16))")
            }
            let chunk = Int(min(end - cursor + 1, region.vaEnd - cursor))
            let offsetInRegion = Int(cursor - region.vaStart)
            segments.append((region.hostBase.advanced(by: offsetInRegion), chunk))
            cursor += UInt64(chunk)
        }
        return segments
    }
}

final class HypervisorEngine: GuestEngine {
    let runtime: HypervisorRuntime
    let cancellation: Cancellation
    let id: UInt64
    let asid: UInt8
    let ttbr0: UInt64
    var emulatesUnsupportedInstructions: Bool { false }
    var needsTLBFlush = false

    private var registers = RegisterSnapshot()
    private let addressSpace: GuestAddressSpace
    private var serviceRange: Range<UInt64>?
    private var serviceHandler: ((UInt64) -> Void)?
    private let stopLock = NSLock()
    private var stopped = false
    private var hasExecuted = false

    init(runtime: HypervisorRuntime, cancellation: Cancellation) throws {
        self.runtime = runtime
        self.cancellation = cancellation
        let (identity, space) = try runtime.performSync {
            let identity = runtime.allocateEngineIdentity()
            do {
                return (identity, try GuestAddressSpace(runtime: runtime))
            } catch {
                runtime.releaseASID(identity.asid)
                throw error
            }
        }
        self.id = identity.id
        self.asid = identity.asid
        self.addressSpace = space
        self.ttbr0 = space.l0Table.ipa | (UInt64(identity.asid) << 48)
    }

    deinit {
        let space = addressSpace
        let asidToFree = asid
        let runtime = runtime
        // `activeEngine` is weak, so it already reads nil here.
        try? runtime.performSync {
            space.reclaim()
            runtime.releaseASID(asidToFree)
        }
    }

    func map(_ address: UInt64, _ size: UInt64) throws {
        try require(size > 0 && size <= 1 << 30, "Invalid guest mapping size")
        try require(address % ARM64.guestPageSize == 0 && size % ARM64.guestPageSize == 0,
                    "Guest mapping must be 4 KiB aligned")
        let end = try guestAddress(address, offset: size - 1)
        try require(end < ARM64.maxGuestVA, "Guest mapping exceeds 47-bit virtual address space")
        try runtime.performSync {
            try addressSpace.map(address, size)
            if hasExecuted { needsTLBFlush = true }
        }
    }

    func read(_ address: UInt64, _ size: UInt64) throws -> Data {
        try require(size <= 64 << 20, "Guest transfer exceeds 64 MiB")
        if size == 0 { return Data() }
        return try runtime.performSync {
            let segments = try addressSpace.resolvePages(for: address, count: size)
            var data = Data(count: Int(size))
            data.withUnsafeMutableBytes { dst in
                guard let base = dst.baseAddress else { return }
                var offset = 0
                for segment in segments {
                    base.advanced(by: offset).copyMemory(from: segment.host, byteCount: segment.count)
                    offset += segment.count
                }
            }
            return data
        }
    }

    func write(_ address: UInt64, _ data: Data) throws {
        if data.isEmpty { return }
        try require(data.count <= 64 << 20, "Guest transfer exceeds 64 MiB")
        try runtime.performSync {
            let segments = try addressSpace.resolvePages(for: address, count: UInt64(data.count))
            data.withUnsafeBytes { src in
                guard let base = src.baseAddress else { return }
                var offset = 0
                for segment in segments {
                    segment.host.copyMemory(from: base.advanced(by: offset), byteCount: segment.count)
                    sys_icache_invalidate(segment.host, segment.count)
                    offset += segment.count
                }
            }
        }
    }

    func register(_ reg: GuestRegister) throws -> UInt64 {
        if case .x(let index) = reg { try require((0...30).contains(index), "Invalid guest register x\(index)") }
        return try runtime.performSync {
            let live = runtime.activeEngine === self
            switch reg {
            case .x(let index): return live ? try runtime.readReg(hv_reg_t(UInt32(index))) : registers.x[index]
            case .sp: return live ? try runtime.readSysReg(HV_SYS_REG_SP_EL1) : registers.spEL1
            case .pc: return live ? try runtime.readReg(HV_REG_PC) : registers.pc
            }
        }
    }

    func register(_ reg: GuestRegister, _ value: UInt64) throws {
        if case .x(let index) = reg { try require((0...30).contains(index), "Invalid guest register x\(index)") }
        try runtime.performSync {
            let live = runtime.activeEngine === self
            switch reg {
            case .x(let index): if live { try runtime.writeReg(hv_reg_t(UInt32(index)), value) } else { registers.x[index] = value }
            case .sp: if live { try runtime.writeSysReg(HV_SYS_REG_SP_EL1, value) } else { registers.spEL1 = value }
            case .pc: if live { try runtime.writeReg(HV_REG_PC, value) } else { registers.pc = value }
            }
        }
    }

    func vector(_ index: Int) throws -> Data {
        try require((0...31).contains(index), "Invalid guest vector register v\(index)")
        return try runtime.performSync {
            if runtime.activeEngine === self {
                return try runtime.readSIMD(index)
            }
            return registers.q[index]
        }
    }

    func vector(_ index: Int, _ data: Data) throws {
        try require((0...31).contains(index), "Invalid guest vector register v\(index)")
        try require(data.count == 16, "Invalid vector register width")
        try runtime.performSync {
            if runtime.activeEngine === self {
                try runtime.writeSIMD(index, data)
                return
            }
            registers.q[index] = data
        }
    }

    func writeReturnTrap(at address: UInt64) throws {
        try write(address, ARM64.hvc1)
    }

    func installServiceStub(at address: UInt64) throws {
        try write(address, Data.littleEndian(ARM64.hvc0) + Data.littleEndian(ARM64.ret))
    }

    func installServiceDispatcher(range: Range<UInt64>, handler: @escaping (UInt64) -> Void) throws {
        try require(!range.isEmpty, "Invalid guest service range")
        try runtime.performSync {
            serviceRange = range
            serviceHandler = handler
        }
    }

    func start(_ begin: UInt64, until end: UInt64, timeout: UInt64) throws {
        try cancellation.check()
        try runtime.performSync {
            setStopped(false)
            hasExecuted = true
            try register(.pc, begin)
            let deadlineCval: UInt64?
            if timeout > 0 {
                let numer = UInt64(runtime.timebase.numer)
                let denom = UInt64(runtime.timebase.denom)
                let (nanos, overflow) = timeout.multipliedReportingOverflow(by: 1000)
                let ticks: UInt64
                if overflow {
                    ticks = (timeout / numer) * 1000 * denom
                } else {
                    let product = nanos.multipliedFullWidth(by: denom)
                    ticks = product.high == 0 ? product.low / numer : UInt64.max / 2
                }
                let now = mach_absolute_time() &- runtime.vtimerOffset
                deadlineCval = now &+ ticks
            } else {
                deadlineCval = nil
            }
            try runLoop(until: end, deadlineCval: deadlineCval)
        }
    }

    private func runLoop(until end: UInt64, deadlineCval: UInt64?) throws {
        while true {
            try cancellation.check()
            try runtime.activate(self)
            let exit = try runtime.runSingleStep(cancellation: cancellation, deadlineCval: deadlineCval)
            switch exit.reason {
            case HV_EXIT_REASON_CANCELED:
                try cancellation.check()
                continue
            case HV_EXIT_REASON_VTIMER_ACTIVATED:
                if let deadlineCval, (mach_absolute_time() &- runtime.vtimerOffset) >= deadlineCval {
                    throw AnisetteError("Guest execution timed out")
                }
                continue
            case HV_EXIT_REASON_EXCEPTION:
                if try handleException(exit.exception, until: end) { return }
            default:
                throw AnisetteError("Hypervisor exited with unexpected reason \(exit.reason.rawValue)")
            }
        }
    }

    private func handleException(_ exception: hv_vcpu_exit_exception_t, until end: UInt64) throws -> Bool {
        let syndrome = exception.syndrome
        let ec = (syndrome >> 26) & 0x3f
        let pc = try runtime.readReg(HV_REG_PC)
        guard ec == ARM64.ecHVC64 else {
            throw AnisetteError(
                "Unexpected VM exit EC=0x\(String(ec, radix: 16)) syndrome=0x\(String(syndrome, radix: 16)) "
                    + "at 0x\(String(pc, radix: 16))"
            )
        }
        let imm = syndrome & 0xffff
        let hvcPC = pc &- 4
        switch imm {
        case 0:
            guard let range = serviceRange, range.contains(hvcPC), let handler = serviceHandler else {
                throw AnisetteError("Unexpected HVC #0 at 0x\(String(hvcPC, radix: 16))")
            }
            setStopped(false)
            handler(hvcPC)
            try cancellation.check()
            return isStopped()
        case 1:
            guard hvcPC == end else {
                throw AnisetteError("Unexpected HVC #1 at 0x\(String(hvcPC, radix: 16))")
            }
            try runtime.writeReg(HV_REG_PC, hvcPC)
            return true
        case 0xffff:
            let elr = try runtime.readSysReg(HV_SYS_REG_ELR_EL1)
            let esr = try runtime.readSysReg(HV_SYS_REG_ESR_EL1)
            let far = try runtime.readSysReg(HV_SYS_REG_FAR_EL1)
            try runtime.writeReg(HV_REG_PC, elr)
            throw AnisetteError(
                "Guest exception ELR=0x\(String(elr, radix: 16)) ESR=0x\(String(esr, radix: 16)) FAR=0x\(String(far, radix: 16))"
            )
        default:
            throw AnisetteError("Unexpected HVC #0x\(String(imm, radix: 16)) at 0x\(String(hvcPC, radix: 16))")
        }
    }

    func stop() {
        setStopped(true)
        if !runtime.isCurrentThread {
            runtime.requestExit()
        }
    }

    private func setStopped(_ value: Bool) {
        stopLock.lock()
        stopped = value
        stopLock.unlock()
    }

    private func isStopped() -> Bool {
        stopLock.lock()
        defer { stopLock.unlock() }
        return stopped
    }

    /// Registers saved and restored on a context switch, besides x0-x30 and q0-q31.
    nonisolated(unsafe) private static let systemRegisters: [(hv_sys_reg_t, WritableKeyPath<RegisterSnapshot, UInt64>)] = [
        (HV_SYS_REG_SP_EL1, \.spEL1), (HV_SYS_REG_SP_EL0, \.spEL0),
        (HV_SYS_REG_TPIDR_EL0, \.tpidrEL0), (HV_SYS_REG_TPIDRRO_EL0, \.tpidrROEL0), (HV_SYS_REG_TPIDR_EL1, \.tpidrEL1),
        (HV_SYS_REG_ELR_EL1, \.elrEL1), (HV_SYS_REG_ESR_EL1, \.esrEL1), (HV_SYS_REG_FAR_EL1, \.farEL1),
        (HV_SYS_REG_SPSR_EL1, \.spsrEL1), (HV_SYS_REG_CONTEXTIDR_EL1, \.contextidrEL1),
    ]
    nonisolated(unsafe) private static let coreRegisters: [(hv_reg_t, WritableKeyPath<RegisterSnapshot, UInt64>)] = [
        (HV_REG_CPSR, \.cpsr), (HV_REG_FPCR, \.fpcr), (HV_REG_FPSR, \.fpsr), (HV_REG_PC, \.pc),
    ]

    func saveFromVCPU(_ runtime: HypervisorRuntime) throws {
        for index in 0..<31 {
            registers.x[index] = try runtime.readReg(hv_reg_t(UInt32(index)))
        }
        for index in 0..<32 {
            registers.q[index] = try runtime.readSIMD(index)
        }
        for (reg, path) in Self.systemRegisters { registers[keyPath: path] = try runtime.readSysReg(reg) }
        for (reg, path) in Self.coreRegisters { registers[keyPath: path] = try runtime.readReg(reg) }
    }

    func loadIntoVCPU(_ runtime: HypervisorRuntime) throws {
        try runtime.writeSysReg(HV_SYS_REG_TTBR0_EL1, ttbr0)
        try runtime.writeSysReg(HV_SYS_REG_VBAR_EL1, ARM64.vbarGuestVA)
        for (reg, path) in Self.systemRegisters { try runtime.writeSysReg(reg, registers[keyPath: path]) }
        for (reg, path) in Self.coreRegisters { try runtime.writeReg(reg, registers[keyPath: path]) }
        for index in 0..<31 {
            try runtime.writeReg(hv_reg_t(UInt32(index)), registers.x[index])
        }
        for index in 0..<32 {
            try runtime.writeSIMD(index, registers.q[index])
        }
    }
}
#endif
