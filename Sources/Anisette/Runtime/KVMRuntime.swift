#if os(Linux) && arch(arm64)
import Foundation
import CAnisette
#if canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#endif

/// Tracks reusable KVM user memory slot indices up to `KVM_CAP_NR_MEMSLOTS`.
private final class MemslotAllocator {
    private let maxSlots: UInt32
    private var nextSlot: UInt32 = 0
    private var freeSlots: [UInt32] = []

    init(maxSlots: UInt32) {
        self.maxSlots = maxSlots
    }

    func allocate() throws -> UInt32 {
        if let reused = freeSlots.popLast() { return reused }
        try require(nextSlot < maxSlots, "KVM memory slots exhausted")
        let slot = nextSlot
        nextSlot += 1
        return slot
    }

    func release(_ slot: UInt32) {
        freeSlots.append(slot)
    }
}

/// Host anonymous mmap slab mapped into the KVM VM at a 16 KiB-aligned IPA.
struct KVMSlab: GuestSlab {
    let slot: UInt32
    let host: UnsafeMutableRawPointer
    let ipa: UInt64
    let size: Int

    fileprivate static func allocate(
        size: Int,
        kvm: OpaquePointer,
        allocator: IPAAllocator,
        slots: MemslotAllocator
    ) throws -> KVMSlab {
        try require(size > 0 && UInt64(size) % ARM64.ipaSlabSize == 0, "Invalid KVM slab size")
        let ipa = try allocator.allocate(UInt64(size))
        let slot: UInt32
        do {
            slot = try slots.allocate()
        } catch {
            allocator.release(ipa..<ipa + UInt64(size))
            throw error
        }
        guard let hostPtr = anisette_kvm_alloc_slab(size) else {
            let err = errno
            slots.release(slot)
            allocator.release(ipa..<ipa + UInt64(size))
            throw AnisetteError("KVM memory allocation failed: \(String(cString: strerror(err)))")
        }
        if anisette_kvm_map_region(kvm, slot, ipa, hostPtr, UInt64(size)) != 0 {
            let err = errno
            anisette_kvm_free_slab(hostPtr, size)
            slots.release(slot)
            allocator.release(ipa..<ipa + UInt64(size))
            throw AnisetteError("KVM memory map failed: \(String(cString: strerror(err)))")
        }
        return KVMSlab(slot: slot, host: hostPtr, ipa: ipa, size: size)
    }

    fileprivate func release(kvm: OpaquePointer, allocator: IPAAllocator, slots: MemslotAllocator) {
        _ = anisette_kvm_map_region(kvm, slot, ipa, host, 0)
        anisette_kvm_free_slab(host, size)
        slots.release(slot)
        allocator.release(ipa..<ipa + UInt64(size))
    }
}

/// Process-wide Linux ARM64 `/dev/kvm` VM + single vCPU singleton confined to `thread`.
final class KVMRuntime: ARM64VCPU, @unchecked Sendable {
    static let availability: Result<KVMRuntime, AnisetteError> = initializeRuntime()

    private static func unavailable(_ message: String) -> Result<KVMRuntime, AnisetteError> {
        .failure(AnisetteError("KVM backend is unavailable (\(message))"))
    }

    private static func initializeRuntime() -> Result<KVMRuntime, AnisetteError> {
        let thread = GuestWorkerThread(name: "anisette.kvm")
        do {
            return try thread.performSync {
                if let cluster = ARM64CPUTopology.detectPreferredCluster() {
                    _ = cluster.map(Int32.init).withUnsafeBufferPointer { anisette_kvm_pin_cpus($0.baseAddress, $0.count) }
                }
                var kickSignal: Int32 = 0
                guard anisette_kvm_setup_worker_thread(&kickSignal) == 0 else {
                    return unavailable("worker signal setup failed: \(String(cString: strerror(errno)))")
                }
                var errorBuf = [CChar](repeating: 0, count: 256)
                guard let kvm = anisette_kvm_create(kickSignal, &errorBuf, errorBuf.count) else {
                    let message = errorBuf.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
                    return unavailable(message.isEmpty ? "KVM initialization failed" : message)
                }
                do {
                    return .success(try KVMRuntime(thread: thread, kvm: kvm, kickSignal: kickSignal))
                } catch {
                    anisette_kvm_destroy(kvm)
                    return unavailable("\(error)")
                }
            }
        } catch {
            return unavailable("\(error)")
        }
    }

    static func trap(_ imm: UInt16) -> UInt32 { ARM64.brk(imm) }
    static let trapMnemonic = "BRK"

    static func invalidateICache(_ address: UnsafeMutableRawPointer, _ size: Int) {
        anisette_kvm_icache_invalidate(address, size)
    }

    private let thread: GuestWorkerThread
    private let kvm: OpaquePointer
    private let kickSignal: Int32
    let ipaAllocator: IPAAllocator
    private let memslots: MemslotAllocator
    private let trampolineTTBR0: UInt64

    // Confined to `thread` except `exitLock`/`running`/`kicked`.
    let asidAllocator = ASIDAllocator()
    weak var activeEngine: ARM64Engine<KVMRuntime>?
    private var activeDeadline: UInt64?

    private let exitLock = NSLock()
    private var running = false
    private var kicked = false

    private init(thread: GuestWorkerThread, kvm: OpaquePointer, kickSignal: Int32) throws {
        self.thread = thread
        self.kvm = kvm
        self.kickSignal = kickSignal
        var mmfr0: UInt64 = 0
        try Self.check(anisette_kvm_get_reg(kvm, ANISETTE_KVM_REG_ID_AA64MMFR0_EL1, &mmfr0), "read ID_AA64MMFR0_EL1")
        guard let stage1 = ARM64.stage1Configuration(ipaBits: Int(anisette_kvm_ipa_bits(kvm)), mmfr0: mmfr0) else {
            throw AnisetteError("4 KiB Stage-1 translation granule or IPA space is unsupported")
        }
        ipaAllocator = IPAAllocator(base: ARM64.ipaBase, limit: stage1.ipaLimit)
        memslots = MemslotAllocator(maxSlots: anisette_kvm_max_memslots(kvm))
        let trampolineSlab = try KVMSlab.allocate(
            size: Int(ARM64.trampolineSlabSize),
            kvm: kvm,
            allocator: ipaAllocator,
            slots: memslots
        )
        trampolineTTBR0 = ARM64.writeTLBITrampoline(
            into: trampolineSlab,
            trapInstruction: Self.trap(2),
            invalidateICache: Self.invalidateICache
        )
        try setReg(ANISETTE_KVM_REG_CPACR_EL1, ARM64.cpacrFPEN)
        try setReg(ANISETTE_KVM_REG_MAIR_EL1, ARM64.mairNormalWB)
        try setReg(ANISETTE_KVM_REG_TCR_EL1, stage1.tcr)
        try setReg(ANISETTE_KVM_REG_SCTLR_EL1, ARM64.sctlrEL1)
        try setReg(ANISETTE_KVM_REG_VBAR_EL1, ARM64.vbarGuestVA)
    }

    var isCurrentThread: Bool { thread.isCurrentThread }

    func performSync<T>(_ body: () throws -> T) throws -> T {
        try thread.performSync(body)
    }

    func requestExit() {
        exitLock.lock()
        if running {
            kicked = true
            pthread_kill(thread.handle, kickSignal)
        }
        exitLock.unlock()
    }

    func allocateSlab(size: Int) throws -> KVMSlab {
        try KVMSlab.allocate(size: size, kvm: kvm, allocator: ipaAllocator, slots: memslots)
    }

    func releaseSlab(_ slab: KVMSlab) {
        slab.release(kvm: kvm, allocator: ipaAllocator, slots: memslots)
    }

    func invalidateTLB(restoringTTBR0 ttbr0: UInt64) throws {
        let savedPC = try read(.pc)
        try write(.ttbr0EL1, trampolineTTBR0)
        try write(.pc, ARM64.trampolineVA)
        while true {
            var exit = anisette_kvm_exit()
            try Self.check(anisette_kvm_run(kvm, &exit), "run TLBI trampoline")
            if exit.kind == ANISETTE_KVM_EXIT_INTR { continue }
            guard exit.kind == ANISETTE_KVM_EXIT_DEBUG else {
                throw AnisetteError("TLBI trampoline exited unexpectedly (\(exit.raw_reason))")
            }
            let ec = (exit.syndrome >> 26) & 0x3f
            let imm = exit.syndrome & 0xffff
            guard ec == ARM64.ecBRK64, imm == 2 else {
                throw AnisetteError("TLBI trampoline faulted (0x\(String(exit.syndrome, radix: 16)))")
            }
            break
        }
        try write(.ttbr0EL1, ttbr0)
        try write(.pc, savedPC)
    }

    func deadline(afterMicroseconds timeout: UInt64) -> UInt64 {
        let (nanos, overflow) = timeout.multipliedReportingOverflow(by: 1000)
        let (target, addOverflow) = anisette_kvm_monotonic_ns().addingReportingOverflow(overflow ? UInt64.max / 2 : nanos)
        return addOverflow ? UInt64.max : target
    }

    /// Arms the deadline timer for `body`; nested invocations restore the enclosing deadline.
    func withDeadline<T>(_ deadline: UInt64?, _ body: () throws -> T) throws -> T {
        let previous = activeDeadline
        setDeadline(deadline)
        defer { setDeadline(previous) }
        return try body()
    }

    private func setDeadline(_ deadline: UInt64?) {
        activeDeadline = deadline
        _ = anisette_kvm_set_deadline(kvm, deadline ?? 0)
        if deadline == nil { anisette_kvm_drain_kick(kickSignal) }
    }

    func run(cancellation: Cancellation, deadline: UInt64?) throws -> ARM64Exit {
        if let deadline, anisette_kvm_monotonic_ns() >= deadline {
            throw AnisetteError("Guest execution timed out")
        }
        exitLock.lock()
        running = true
        exitLock.unlock()

        var exit = anisette_kvm_exit()
        // Checked after publishing `running` so a concurrent cancel either is seen here or kicks the run.
        let rc = cancellation.isCancelled ? nil : anisette_kvm_run(kvm, &exit)
        let runErrno = errno

        exitLock.lock()
        running = false
        let wasKicked = kicked
        kicked = false
        exitLock.unlock()
        if wasKicked { anisette_kvm_drain_kick(kickSignal) }

        guard let rc else { throw CancellationError() }
        if rc != 0 {
            throw AnisetteError("KVM vcpu run failed: \(String(cString: strerror(runErrno)))")
        }
        try cancellation.check()

        switch exit.kind {
        case ANISETTE_KVM_EXIT_INTR:
            if let deadline, anisette_kvm_monotonic_ns() >= deadline {
                throw AnisetteError("Guest execution timed out")
            }
            return .interrupted
        case ANISETTE_KVM_EXIT_DEBUG:
            let syndrome = exit.syndrome
            let ec = (syndrome >> 26) & 0x3f
            let pc = try read(.pc)
            guard ec == ARM64.ecBRK64 else {
                throw AnisetteError(
                    "Unexpected KVM debug exit EC=0x\(String(ec, radix: 16)) syndrome=0x\(String(syndrome, radix: 16)) "
                        + "at 0x\(String(pc, radix: 16))"
                )
            }
            return .trap(imm: syndrome & 0xffff, address: pc)
        case ANISETTE_KVM_EXIT_MMIO:
            let pc = try read(.pc)
            throw AnisetteError(
                "Unexpected KVM MMIO exit at 0x\(String(pc, radix: 16)) (IPA 0x\(String(exit.detail, radix: 16)))"
            )
        default:
            throw AnisetteError(
                "KVM exited with unexpected reason \(exit.raw_reason) (detail 0x\(String(exit.detail, radix: 16)))"
            )
        }
    }

    private static func check(_ rc: Int32, _ context: @autoclosure () -> String) throws {
        if rc != 0 {
            throw AnisetteError("KVM \(context()) failed: \(String(cString: strerror(errno)))")
        }
    }

    private static func kvmRegister(_ reg: ARM64Register) -> anisette_kvm_reg {
        switch reg {
        case .x(let index): anisette_kvm_reg(ANISETTE_KVM_REG_X0.rawValue + UInt32(index))
        case .spEL0: ANISETTE_KVM_REG_SP_EL0
        case .spEL1: ANISETTE_KVM_REG_SP_EL1
        case .pc: ANISETTE_KVM_REG_PC
        case .cpsr: ANISETTE_KVM_REG_PSTATE
        case .fpcr: ANISETTE_KVM_REG_FPCR
        case .fpsr: ANISETTE_KVM_REG_FPSR
        case .elrEL1: ANISETTE_KVM_REG_ELR_EL1
        case .spsrEL1: ANISETTE_KVM_REG_SPSR_EL1
        case .esrEL1: ANISETTE_KVM_REG_ESR_EL1
        case .farEL1: ANISETTE_KVM_REG_FAR_EL1
        case .tpidrEL0: ANISETTE_KVM_REG_TPIDR_EL0
        case .tpidrROEL0: ANISETTE_KVM_REG_TPIDRRO_EL0
        case .tpidrEL1: ANISETTE_KVM_REG_TPIDR_EL1
        case .contextidrEL1: ANISETTE_KVM_REG_CONTEXTIDR_EL1
        case .ttbr0EL1: ANISETTE_KVM_REG_TTBR0_EL1
        }
    }

    private func setReg(_ reg: anisette_kvm_reg, _ value: UInt64) throws {
        try Self.check(anisette_kvm_set_reg(kvm, reg, value), "write register \(reg.rawValue)")
    }

    func read(_ reg: ARM64Register) throws -> UInt64 {
        let kvmReg = Self.kvmRegister(reg)
        var value: UInt64 = 0
        try Self.check(anisette_kvm_get_reg(kvm, kvmReg, &value), "read register \(kvmReg.rawValue)")
        return value
    }

    func write(_ reg: ARM64Register, _ value: UInt64) throws {
        try setReg(Self.kvmRegister(reg), value)
    }

    func readSIMD(_ index: Int) throws -> Data {
        var data = Data(count: 16)
        try data.withUnsafeMutableBytes { dst in
            try Self.check(anisette_kvm_get_vreg(kvm, UInt32(index), dst.baseAddress), "read Q\(index)")
        }
        return data
    }

    func writeSIMD(_ index: Int, _ data: Data) throws {
        try require(data.count == 16, "Invalid vector register width")
        try data.withUnsafeBytes { src in
            try Self.check(anisette_kvm_set_vreg(kvm, UInt32(index), src.baseAddress), "write Q\(index)")
        }
    }
}
#endif
