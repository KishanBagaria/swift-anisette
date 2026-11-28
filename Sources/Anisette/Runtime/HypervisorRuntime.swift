#if os(macOS) && arch(arm64)
import Foundation
import Darwin
import Hypervisor

/// Host memory mapped into the Hypervisor.framework VM at a 16 KiB-aligned IPA.
struct HypervisorSlab: GuestSlab {
    let host: UnsafeMutableRawPointer
    let ipa: UInt64
    let size: Int

    static func allocate(size: Int, from allocator: IPAAllocator) throws -> HypervisorSlab {
        try require(size > 0 && UInt64(size) % ARM64.ipaSlabSize == 0, "Invalid Hypervisor slab size")
        let ipa = try allocator.allocate(UInt64(size))
        var rawPtr: UnsafeMutableRawPointer?
        let allocRC = hv_vm_allocate(&rawPtr, size, hv_allocate_flags_t(HV_ALLOCATE_DEFAULT))
        guard allocRC == HV_SUCCESS, let hostPtr = rawPtr else {
            allocator.release(ipa..<ipa + UInt64(size))
            throw AnisetteError("Hypervisor memory allocation failed: \(HypervisorRuntime.formatStatus(allocRC))")
        }
        let flags = hv_memory_flags_t(HV_MEMORY_READ | HV_MEMORY_WRITE | HV_MEMORY_EXEC)
        let mapRC = hv_vm_map(hostPtr, ipa, size, flags)
        guard mapRC == HV_SUCCESS else {
            _ = hv_vm_deallocate(hostPtr, size)
            allocator.release(ipa..<ipa + UInt64(size))
            throw AnisetteError("Hypervisor memory map failed: \(HypervisorRuntime.formatStatus(mapRC))")
        }
        return HypervisorSlab(host: hostPtr, ipa: ipa, size: size)
    }

    func release(to allocator: IPAAllocator) {
        _ = hv_vm_unmap(ipa, size)
        _ = hv_vm_deallocate(host, size)
        allocator.release(ipa..<ipa + UInt64(size))
    }
}

/// Process-wide Hypervisor VM + single vCPU singleton confined to `thread`.
final class HypervisorRuntime: ARM64VCPU, @unchecked Sendable {
    private enum Availability {
        case available(HypervisorRuntime)
        case unavailable(hv_return_t, String)
    }

    private static let cachedAvailability: Availability = initializeRuntime()

    static var isAvailable: Bool {
        if case .available = cachedAvailability { return true }
        return false
    }

    static func shared() throws -> HypervisorRuntime {
        switch cachedAvailability {
        case .available(let runtime):
            return runtime
        case .unavailable(let code, let message):
            throw unavailableError(code: code, message: message)
        }
    }

    private static func unavailableError(code: hv_return_t, message: String) -> AnisetteError {
        if code == hv_return_t(HV_DENIED) {
            return AnisetteError("Hypervisor backend is unavailable (HV_DENIED: missing com.apple.security.hypervisor entitlement)")
        }
        if code == hv_return_t(HV_UNSUPPORTED) || code == hv_return_t(HV_NO_DEVICE) {
            return AnisetteError("Hypervisor backend is unsupported on this host (\(message))")
        }
        return AnisetteError("Hypervisor backend is unavailable (\(message))")
    }

    static func formatStatus(_ code: hv_return_t) -> String {
        "0x\(String(UInt32(bitPattern: code), radix: 16))"
    }

    private static func initializeRuntime() -> Availability {
        let thread = GuestWorkerThread(name: "swift-anisette.hypervisor")
        do {
            return try thread.performSync {
                let vmStatus = hv_vm_create(nil)
                guard vmStatus == HV_SUCCESS else {
                    return .unavailable(vmStatus, "hv_vm_create failed: \(formatStatus(vmStatus))")
                }
                var vcpu: hv_vcpu_t = 0
                var exitPointer: UnsafeMutablePointer<hv_vcpu_exit_t>?
                let vcpuStatus = hv_vcpu_create(&vcpu, &exitPointer, nil)
                guard vcpuStatus == HV_SUCCESS, let exitPointer else {
                    _ = hv_vm_destroy()
                    return .unavailable(vcpuStatus, "hv_vcpu_create failed: \(formatStatus(vcpuStatus))")
                }
                return try finishSetup(thread: thread, vcpu: vcpu, exitPointer: exitPointer)
            }
        } catch {
            return .unavailable(hv_return_t(HV_ERROR), "\(error)")
        }
    }

    private static func finishSetup(
        thread: GuestWorkerThread,
        vcpu: hv_vcpu_t,
        exitPointer: UnsafeMutablePointer<hv_vcpu_exit_t>
    ) throws -> Availability {
        var mmfr0: UInt64 = 0
        guard hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ID_AA64MMFR0_EL1, &mmfr0) == HV_SUCCESS else {
            _ = hv_vcpu_destroy(vcpu)
            _ = hv_vm_destroy()
            return .unavailable(hv_return_t(HV_UNSUPPORTED), "Cannot read ID_AA64MMFR0_EL1")
        }
        var ipaBits: UInt32 = 36
        if hv_vm_config_get_default_ipa_size(&ipaBits) != HV_SUCCESS { ipaBits = 36 }
        guard let stage1 = ARM64.stage1Configuration(ipaBits: Int(ipaBits), mmfr0: mmfr0) else {
            _ = hv_vcpu_destroy(vcpu)
            _ = hv_vm_destroy()
            return .unavailable(hv_return_t(HV_UNSUPPORTED), "4 KiB Stage-1 translation granule or IPA space is unsupported")
        }
        var vtimerOffset: UInt64 = 0
        _ = hv_vcpu_get_vtimer_offset(vcpu, &vtimerOffset)
        var timebase = mach_timebase_info_data_t()
        mach_timebase_info(&timebase)

        let ipaAllocator = IPAAllocator(base: ARM64.ipaBase, limit: stage1.ipaLimit)
        let trampolineSlab = try HypervisorSlab.allocate(size: Int(ARM64.ipaSlabSize * 2), from: ipaAllocator)
        let trampolineTTBR0 = ARM64.writeTLBITrampoline(
            into: trampolineSlab,
            trapInstruction: ARM64.hvc2,
            invalidateICache: sys_icache_invalidate
        )

        let runtime = HypervisorRuntime(
            thread: thread,
            vcpu: vcpu,
            exitPointer: exitPointer,
            vtimerOffset: vtimerOffset,
            timebase: timebase,
            ipaAllocator: ipaAllocator,
            trampolineTTBR0: trampolineTTBR0
        )
        try runtime.configureConstantSystemRegisters(tcr: stage1.tcr)
        return .available(runtime)
    }

    static let serviceTrap = ARM64.hvc0
    static let returnTrap = ARM64.hvc1
    static let vectorTrap = ARM64.hvcFFFF
    static let trapMnemonic = "HVC"
    static let trapAdvancesPC = true

    static func invalidateICache(_ address: UnsafeMutableRawPointer, _ size: Int) {
        sys_icache_invalidate(address, size)
    }

    private let thread: GuestWorkerThread
    private let vcpu: hv_vcpu_t
    private let exitPointer: UnsafeMutablePointer<hv_vcpu_exit_t>
    private let vtimerOffset: UInt64
    private let timebase: mach_timebase_info_data_t
    let ipaAllocator: IPAAllocator
    private let trampolineTTBR0: UInt64

    // All properties below except `exitLock`/`runningVCPU` are confined to `thread`.
    let asidAllocator = ASIDAllocator()
    weak var activeEngine: ARM64Engine<HypervisorRuntime>?

    private let exitLock = NSLock()
    private var runningVCPU: hv_vcpu_t?

    private init(
        thread: GuestWorkerThread,
        vcpu: hv_vcpu_t,
        exitPointer: UnsafeMutablePointer<hv_vcpu_exit_t>,
        vtimerOffset: UInt64,
        timebase: mach_timebase_info_data_t,
        ipaAllocator: IPAAllocator,
        trampolineTTBR0: UInt64
    ) {
        self.thread = thread
        self.vcpu = vcpu
        self.exitPointer = exitPointer
        self.vtimerOffset = vtimerOffset
        self.timebase = timebase
        self.ipaAllocator = ipaAllocator
        self.trampolineTTBR0 = trampolineTTBR0
    }

    private func configureConstantSystemRegisters(tcr: UInt64) throws {
        try hvCheck(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_CPACR_EL1, ARM64.cpacrFPEN), "CPACR_EL1")
        try hvCheck(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_MAIR_EL1, ARM64.mairNormalWB), "MAIR_EL1")
        try hvCheck(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TCR_EL1, tcr), "TCR_EL1")
        try hvCheck(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_SCTLR_EL1, ARM64.sctlrEL1), "SCTLR_EL1")
        try hvCheck(hv_vcpu_set_vtimer_mask(vcpu, true), "vtimer mask")
    }

    var isCurrentThread: Bool { thread.isCurrentThread }

    func performSync<T>(_ body: () throws -> T) throws -> T {
        try thread.performSync(body)
    }

    func requestExit() {
        exitLock.lock()
        let active = runningVCPU
        exitLock.unlock()
        if var active { _ = hv_vcpus_exit(&active, 1) }
    }

    func allocateSlab(size: Int) throws -> HypervisorSlab {
        try HypervisorSlab.allocate(size: size, from: ipaAllocator)
    }

    func releaseSlab(_ slab: HypervisorSlab) {
        slab.release(to: ipaAllocator)
    }

    private func hvCheck(_ code: hv_return_t, _ context: @autoclosure () -> String) throws {
        if code != HV_SUCCESS {
            throw AnisetteError("Hypervisor \(context()) failed: \(Self.formatStatus(code))")
        }
    }

    func invalidateTLB(restoringTTBR0 ttbr0: UInt64) throws {
        if #available(macOS 27.0, *) {
            try hvCheck(hv_vcpu_invalidate_tlb(vcpu, HV_TLBI_OP_VMALLE1IS, 0), "invalidate TLB")
            return
        }
        var savedPC: UInt64 = 0
        try hvCheck(hv_vcpu_get_reg(vcpu, HV_REG_PC, &savedPC), "read PC for TLBI")
        try hvCheck(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_CNTV_CTL_EL0, 0), "disable vtimer for TLBI")
        try hvCheck(hv_vcpu_set_vtimer_mask(vcpu, true), "mask vtimer for TLBI")
        try hvCheck(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TTBR0_EL1, trampolineTTBR0), "set trampoline TTBR0")
        try hvCheck(hv_vcpu_set_reg(vcpu, HV_REG_PC, ARM64.trampolineVA), "set trampoline PC")
        while true {
            try hvCheck(hv_vcpu_run(vcpu), "run TLBI trampoline")
            let exit = exitPointer.pointee
            if exit.reason == HV_EXIT_REASON_CANCELED { continue }
            guard exit.reason == HV_EXIT_REASON_EXCEPTION else {
                throw AnisetteError("TLBI trampoline exited unexpectedly (\(exit.reason.rawValue))")
            }
            let ec = (exit.exception.syndrome >> 26) & 0x3f
            let imm = exit.exception.syndrome & 0xffff
            guard ec == ARM64.ecHVC64, imm == 2 else {
                throw AnisetteError("TLBI trampoline faulted (0x\(String(exit.exception.syndrome, radix: 16)))")
            }
            break
        }
        try hvCheck(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TTBR0_EL1, ttbr0), "restore TTBR0 after TLBI")
        try hvCheck(hv_vcpu_set_reg(vcpu, HV_REG_PC, savedPC), "restore PC after TLBI")
    }

    func deadline(afterMicroseconds timeout: UInt64) -> UInt64 {
        let numer = UInt64(timebase.numer)
        let denom = UInt64(timebase.denom)
        let (nanos, overflow) = timeout.multipliedReportingOverflow(by: 1000)
        let ticks: UInt64
        if overflow {
            ticks = (timeout / numer) * 1000 * denom
        } else {
            let product = nanos.multipliedFullWidth(by: denom)
            ticks = product.high == 0 ? product.low / numer : UInt64.max / 2
        }
        return virtualTime() &+ ticks
    }

    private func virtualTime() -> UInt64 {
        mach_absolute_time() &- vtimerOffset
    }

    /// The virtual timer is programmed per run, so there is no enclosing deadline to restore.
    func withDeadline<T>(_ deadline: UInt64?, _ body: () throws -> T) throws -> T {
        try body()
    }

    func run(cancellation: Cancellation, deadline: UInt64?) throws -> ARM64Exit {
        if let deadline {
            if virtualTime() >= deadline { throw AnisetteError("Guest execution timed out") }
            try hvCheck(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_CNTV_CVAL_EL0, deadline), "set CNTV_CVAL_EL0")
            try hvCheck(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_CNTV_CTL_EL0, 1), "enable CNTV_CTL_EL0")
            try hvCheck(hv_vcpu_set_vtimer_mask(vcpu, false), "unmask vtimer")
        } else {
            try hvCheck(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_CNTV_CTL_EL0, 0), "disable CNTV_CTL_EL0")
            try hvCheck(hv_vcpu_set_vtimer_mask(vcpu, true), "mask vtimer")
        }
        exitLock.lock()
        runningVCPU = vcpu
        exitLock.unlock()
        guard let cancelID = cancellation.addHandler({ [weak self] in self?.requestExit() }) else {
            exitLock.lock()
            runningVCPU = nil
            exitLock.unlock()
            throw CancellationError()
        }
        let rc = hv_vcpu_run(vcpu)
        cancellation.removeHandler(cancelID)
        exitLock.lock()
        runningVCPU = nil
        exitLock.unlock()
        _ = hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_CNTV_CTL_EL0, 0)
        _ = hv_vcpu_set_vtimer_mask(vcpu, true)
        try hvCheck(rc, "vcpu run")
        try cancellation.check()

        let exit = exitPointer.pointee
        switch exit.reason {
        case HV_EXIT_REASON_CANCELED:
            return .interrupted
        case HV_EXIT_REASON_VTIMER_ACTIVATED:
            if let deadline, virtualTime() >= deadline { throw AnisetteError("Guest execution timed out") }
            return .interrupted
        case HV_EXIT_REASON_EXCEPTION:
            let syndrome = exit.exception.syndrome
            let ec = (syndrome >> 26) & 0x3f
            let pc = try read(.pc)
            guard ec == ARM64.ecHVC64 else {
                throw AnisetteError(
                    "Unexpected VM exit EC=0x\(String(ec, radix: 16)) syndrome=0x\(String(syndrome, radix: 16)) "
                        + "at 0x\(String(pc, radix: 16))"
                )
            }
            return .trap(imm: syndrome & 0xffff, address: pc &- 4)
        default:
            throw AnisetteError("Hypervisor exited with unexpected reason \(exit.reason.rawValue)")
        }
    }

    private enum Location: Sendable {
        case core(hv_reg_t)
        case system(hv_sys_reg_t)
    }

    private static let registerLocations: [ARM64Register: Location] = [
        .pc: .core(HV_REG_PC), .cpsr: .core(HV_REG_CPSR), .fpcr: .core(HV_REG_FPCR), .fpsr: .core(HV_REG_FPSR),
        .spEL0: .system(HV_SYS_REG_SP_EL0), .spEL1: .system(HV_SYS_REG_SP_EL1),
        .elrEL1: .system(HV_SYS_REG_ELR_EL1), .spsrEL1: .system(HV_SYS_REG_SPSR_EL1),
        .esrEL1: .system(HV_SYS_REG_ESR_EL1), .farEL1: .system(HV_SYS_REG_FAR_EL1),
        .tpidrEL0: .system(HV_SYS_REG_TPIDR_EL0), .tpidrROEL0: .system(HV_SYS_REG_TPIDRRO_EL0),
        .tpidrEL1: .system(HV_SYS_REG_TPIDR_EL1), .contextidrEL1: .system(HV_SYS_REG_CONTEXTIDR_EL1),
        .ttbr0EL1: .system(HV_SYS_REG_TTBR0_EL1), .vbarEL1: .system(HV_SYS_REG_VBAR_EL1),
    ]

    private static func location(of reg: ARM64Register) -> Location {
        if case .x(let index) = reg { return .core(hv_reg_t(UInt32(index))) }
        guard let mapped = registerLocations[reg] else {
            preconditionFailure("Unmapped ARM64Register \(reg)")
        }
        return mapped
    }

    func read(_ reg: ARM64Register) throws -> UInt64 {
        var value: UInt64 = 0
        switch Self.location(of: reg) {
        case .core(let core):
            try hvCheck(hv_vcpu_get_reg(vcpu, core, &value), "read register \(core.rawValue)")
        case .system(let system):
            try hvCheck(hv_vcpu_get_sys_reg(vcpu, system, &value), "read sysreg 0x\(String(system.rawValue, radix: 16))")
        }
        return value
    }

    func write(_ reg: ARM64Register, _ value: UInt64) throws {
        switch Self.location(of: reg) {
        case .core(let core):
            try hvCheck(hv_vcpu_set_reg(vcpu, core, value), "write register \(core.rawValue)")
        case .system(let system):
            try hvCheck(hv_vcpu_set_sys_reg(vcpu, system, value), "write sysreg 0x\(String(system.rawValue, radix: 16))")
        }
    }

    func readSIMD(_ index: Int) throws -> Data {
        var value = hv_simd_fp_uchar16_t()
        try hvCheck(hv_vcpu_get_simd_fp_reg(vcpu, hv_simd_fp_reg_t(UInt32(index)), &value), "read Q\(index)")
        return withUnsafeBytes(of: &value) { Data($0) }
    }

    func writeSIMD(_ index: Int, _ data: Data) throws {
        try require(data.count == 16, "Invalid vector register width")
        var value = hv_simd_fp_uchar16_t()
        _ = withUnsafeMutableBytes(of: &value) { dst in
            data.copyBytes(to: dst.bindMemory(to: UInt8.self))
        }
        try hvCheck(hv_vcpu_set_simd_fp_reg(vcpu, hv_simd_fp_reg_t(UInt32(index)), value), "write Q\(index)")
    }
}
#endif
