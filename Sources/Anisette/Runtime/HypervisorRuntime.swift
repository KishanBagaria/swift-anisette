#if os(macOS) && arch(arm64)
import Foundation
import Darwin
import Hypervisor

enum ARM64 {
    static let guestPageSize: UInt64 = 4096
    static let ipaSlabSize: UInt64 = 16384
    static let maxGuestVA: UInt64 = 0x8000_0000_0000
    static let vbarGuestVA: UInt64 = 0x8000_0000_0000
    static let trampolineVA: UInt64 = 0x8000_0001_0000
    static let hvc0: UInt32 = 0xd4000002
    static let hvc1: UInt32 = 0xd4000022
    static let hvc2: UInt32 = 0xd4000042
    static let hvcFFFF: UInt32 = 0xd41fffe2
    static let ret: UInt32 = 0xd65f03c0
    static let tlbiVMALLE1: UInt32 = 0xd508871f
    static let dsbSY: UInt32 = 0xd5033f9f
    static let isb: UInt32 = 0xd5033fdf
    static let cpsrEL1h: UInt64 = 0x3c5
    static let cpacrFPEN: UInt64 = 0x3 << 20
    static let mairNormalWB: UInt64 = 0xff
    // M | C | I | DZE | UCT | UCI | EOS | EIS | SPAN (A=0 unaligned ok, WXN=0)
    static let sctlrEL1: UInt64 = (1 << 0) | (1 << 2) | (1 << 11) | (1 << 12)
        | (1 << 14) | (1 << 15) | (1 << 22) | (1 << 23) | (1 << 26)
    static let tableDescriptorBits: UInt64 = 0x3
    // Valid page, AttrIndx=0, AP=00 (EL1 RW), SH=11 (Inner Shareable), AF=1, nG=1
    static let rwPageDescriptorBits: UInt64 = (1 << 11) | (1 << 10) | (3 << 8) | 0x3
    // Valid page, AttrIndx=0, AP=10 (EL1 RO), SH=11 (Inner Shareable), AF=1, nG=1
    static let roPageDescriptorBits: UInt64 = (1 << 11) | (1 << 10) | (3 << 8) | (2 << 6) | 0x3
    static let ecHVC64: UInt64 = 0x16
}

/// Dedicated POSIX thread for Hypervisor.framework vCPU affinity (`hv_vcpu_t` is thread-bound).
private final class HypervisorThread: @unchecked Sendable {
    private final class SyncBox<T> {
        var body: (() throws -> T)?
        var result: Result<T, any Error>?
        let done = DispatchSemaphore(value: 0)

        init(_ body: @escaping () throws -> T) {
            self.body = body
        }

        @inline(never)
        func runAndReleaseBody() {
            guard let fn = body else { return }
            body = nil
            result = Result { try fn() }
        }

        func execute() {
            runAndReleaseBody()
            done.signal()
        }
    }

    private let queueCondition = NSCondition()
    private var pendingJobs: [() -> Void] = []
    private var thread: pthread_t?
    private let readySemaphore = DispatchSemaphore(value: 0)

    init() {
        var attributes = pthread_attr_t()
        pthread_attr_init(&attributes)
        pthread_attr_setstacksize(&attributes, 2 << 20)
        let context = Unmanaged.passUnretained(self).toOpaque()
        var created: pthread_t?
        let rc = pthread_create(&created, &attributes, { rawContext in
            let runner = Unmanaged<HypervisorThread>.fromOpaque(rawContext).takeUnretainedValue()
            runner.runLoop()
            return nil
        }, context)
        pthread_attr_destroy(&attributes)
        precondition(rc == 0 && created != nil, "Cannot create Hypervisor worker thread (\(rc))")
        thread = created
        readySemaphore.wait()
    }

    var isCurrentThread: Bool {
        guard let thread else { return false }
        return pthread_equal(pthread_self(), thread) != 0
    }

    private func runLoop() {
        pthread_setname_np("swift-anisette.hypervisor")
        readySemaphore.signal()
        while true {
            queueCondition.lock()
            while pendingJobs.isEmpty { queueCondition.wait() }
            let job = pendingJobs.removeFirst()
            queueCondition.unlock()
            job()
        }
    }

    func performSync<T>(_ body: () throws -> T) throws -> T {
        if isCurrentThread { return try body() }
        return try withoutActuallyEscaping(body) { escapingBody in
            let box = SyncBox(escapingBody)
            queueCondition.lock()
            pendingJobs.append { box.execute() }
            queueCondition.signal()
            queueCondition.unlock()
            box.done.wait()
            guard let result = box.result else {
                throw AnisetteError("Hypervisor worker failed to produce a result")
            }
            return try result.get()
        }
    }
}

/// Coalescing 16 KiB-aligned IPA address allocator for the single process-wide VM.
final class IPAAllocator {
    private let base: UInt64
    private let limit: UInt64
    private var cursor: UInt64
    private var freeRanges: [Range<UInt64>] = []

    init(base: UInt64, limit: UInt64) {
        self.base = base
        self.limit = limit
        self.cursor = base
    }

    func allocate(_ size: UInt64) throws -> UInt64 {
        try require(size > 0 && size % ARM64.ipaSlabSize == 0, "Invalid IPA slab size")
        for index in freeRanges.indices {
            let block = freeRanges[index]
            if block.upperBound - block.lowerBound >= size {
                let start = block.lowerBound
                let end = start + size
                if end < block.upperBound {
                    freeRanges[index] = end..<block.upperBound
                } else {
                    freeRanges.remove(at: index)
                }
                return start
            }
        }
        try require(cursor <= limit - size, "Hypervisor IPA space exhausted")
        let start = cursor
        cursor += size
        return start
    }

    func release(_ range: Range<UInt64>) {
        guard !range.isEmpty else { return }
        var merged = range
        var low = 0, high = freeRanges.count
        while low < high {
            let middle = (low + high) / 2
            if freeRanges[middle].lowerBound < merged.lowerBound { low = middle + 1 } else { high = middle }
        }
        var index = low
        if index < freeRanges.count, freeRanges[index].lowerBound == merged.upperBound {
            merged = merged.lowerBound..<freeRanges.remove(at: index).upperBound
        }
        if index > 0, freeRanges[index - 1].upperBound == merged.lowerBound {
            index -= 1
            merged = freeRanges.remove(at: index).lowerBound..<merged.upperBound
        }
        if merged.upperBound == cursor {
            cursor -= merged.upperBound - merged.lowerBound
        } else {
            freeRanges.insert(merged, at: index)
        }
    }

    var allocatedBytes: UInt64 {
        let freeBytes = freeRanges.reduce(UInt64(0)) { $0 + ($1.upperBound - $1.lowerBound) }
        return (cursor - base) - freeBytes
    }

    var highWaterMark: UInt64 {
        cursor - base
    }
}

/// Host memory mapped into the VM at a 16 KiB-aligned IPA.
struct Slab {
    let host: UnsafeMutableRawPointer
    let ipa: UInt64
    let size: Int

    static func allocate(size: Int, from allocator: IPAAllocator) throws -> Slab {
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
        return Slab(host: hostPtr, ipa: ipa, size: size)
    }

    func release(to allocator: IPAAllocator) {
        _ = hv_vm_unmap(ipa, size)
        _ = hv_vm_deallocate(host, size)
        allocator.release(ipa..<ipa + UInt64(size))
    }
}

/// Process-wide Hypervisor VM + single vCPU singleton confined to `thread`.
final class HypervisorRuntime: @unchecked Sendable {
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
        let thread = HypervisorThread()
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
        thread: HypervisorThread,
        vcpu: hv_vcpu_t,
        exitPointer: UnsafeMutablePointer<hv_vcpu_exit_t>
    ) throws -> Availability {
        var mmfr0: UInt64 = 0
        guard hv_vcpu_get_sys_reg(vcpu, HV_SYS_REG_ID_AA64MMFR0_EL1, &mmfr0) == HV_SUCCESS,
              (mmfr0 >> 28) & 0xf != 0xf else {
            _ = hv_vcpu_destroy(vcpu)
            _ = hv_vm_destroy()
            return .unavailable(hv_return_t(HV_UNSUPPORTED), "4 KiB Stage-1 translation granule is unsupported")
        }
        var ipaBits: UInt32 = 36
        if hv_vm_config_get_default_ipa_size(&ipaBits) != HV_SUCCESS { ipaBits = 36 }
        let paRange = Int(mmfr0 & 0xf)
        let ips = min(paBitsByIPS.firstIndex { $0 >= Int(ipaBits) } ?? paBitsByIPS.count - 1, paRange)
        let effectiveIPABits = min(Int(ipaBits), paBitsByIPS[ips])
        let ipaLimit = effectiveIPABits >= 63 ? UInt64.max : (UInt64(1) << effectiveIPABits)
        let ipaBase: UInt64 = 0x4000_0000
        guard ipaBase < ipaLimit else {
            _ = hv_vcpu_destroy(vcpu)
            _ = hv_vm_destroy()
            return .unavailable(hv_return_t(HV_UNSUPPORTED), "Insufficient IPA space")
        }
        // T0SZ=16 (48-bit VA), IRGN0=1, ORGN0=1, SH0=3, TG0=0 (4 KiB), EPD1=1, TG1=2, IPS=ips
        let tcr: UInt64 = 16 | (1 << 8) | (1 << 10) | (3 << 12) | (1 << 23) | (2 << 30) | (UInt64(ips) << 32)
        var vtimerOffset: UInt64 = 0
        _ = hv_vcpu_get_vtimer_offset(vcpu, &vtimerOffset)
        var timebase = mach_timebase_info_data_t()
        mach_timebase_info(&timebase)

        let ipaAllocator = IPAAllocator(base: ipaBase, limit: ipaLimit)
        let trampolineTTBR0 = try buildTrampoline(ipaAllocator: ipaAllocator)

        let runtime = HypervisorRuntime(
            thread: thread,
            vcpu: vcpu,
            exitPointer: exitPointer,
            vtimerOffset: vtimerOffset,
            timebase: timebase,
            ipaAllocator: ipaAllocator,
            trampolineTTBR0: trampolineTTBR0
        )
        try runtime.configureConstantSystemRegisters(tcr: tcr)
        return .available(runtime)
    }

    /// Physical address bits for each TCR_EL1.IPS encoding.
    private static let paBitsByIPS = [32, 36, 40, 42, 44, 48]

    /// Permanent ASID=0 4-level page table + EL1 TLBI trampoline for macOS < 27 TLB invalidation.
    private static func buildTrampoline(ipaAllocator: IPAAllocator) throws -> UInt64 {
        let slab = try Slab.allocate(size: Int(ARM64.ipaSlabSize * 2), from: ipaAllocator) // 4 page-table pages + 1 code page
        let hostPtr = slab.host, ipa = slab.ipa
        memset(hostPtr, 0, slab.size)
        func writeEntry(tableOffset: Int, index: Int, value: UInt64) {
            hostPtr.storeBytes(of: value.littleEndian, toByteOffset: tableOffset + index * 8, as: UInt64.self)
        }
        let va = ARM64.trampolineVA
        writeEntry(tableOffset: 0x0000, index: Int((va >> 39) & 0x1ff), value: (ipa + 0x1000) | ARM64.tableDescriptorBits)
        writeEntry(tableOffset: 0x1000, index: Int((va >> 30) & 0x1ff), value: (ipa + 0x2000) | ARM64.tableDescriptorBits)
        writeEntry(tableOffset: 0x2000, index: Int((va >> 21) & 0x1ff), value: (ipa + 0x3000) | ARM64.tableDescriptorBits)
        writeEntry(tableOffset: 0x3000, index: Int((va >> 12) & 0x1ff), value: (ipa + 0x4000) | ARM64.roPageDescriptorBits)

        let code: [UInt32] = [ARM64.tlbiVMALLE1, ARM64.dsbSY, ARM64.isb, ARM64.hvc2]
        for (index, word) in code.enumerated() {
            hostPtr.storeBytes(of: word.littleEndian, toByteOffset: 0x4000 + index * 4, as: UInt32.self)
        }
        sys_icache_invalidate(hostPtr.advanced(by: 0x4000), Int(ARM64.guestPageSize))
        return ipa // ASID = 0
    }

    private let thread: HypervisorThread
    private let vcpu: hv_vcpu_t
    private let exitPointer: UnsafeMutablePointer<hv_vcpu_exit_t>
    let vtimerOffset: UInt64
    let timebase: mach_timebase_info_data_t
    private let ipaAllocator: IPAAllocator
    private let trampolineTTBR0: UInt64

    // All properties below except `exitLock`/`runningVCPU` are confined to `thread`.
    private var nextEngineID: UInt64 = 1
    private var asidCursor: Int = 1
    private var asidRefCount = [Int](repeating: 0, count: 256)
    private var lastASIDOwner = [UInt64](repeating: 0, count: 256)
    weak var activeEngine: HypervisorEngine?

    private let exitLock = NSLock()
    private var runningVCPU: hv_vcpu_t?

    private init(
        thread: HypervisorThread,
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

    var userAllocatedIPABytes: UInt64 {
        (try? performSync {
            let total = ipaAllocator.allocatedBytes
            let trampolineBytes = UInt64(ARM64.ipaSlabSize * 2)
            return total >= trampolineBytes ? total - trampolineBytes : 0
        }) ?? 0
    }

    var liveEngineCount: Int {
        (try? performSync { asidRefCount.reduce(0, +) }) ?? 0
    }

    var ipaHighWaterMark: UInt64 {
        (try? performSync { ipaAllocator.highWaterMark }) ?? 0
    }

    func allocateEngineIdentity() -> (id: UInt64, asid: UInt8) {
        let id = nextEngineID
        nextEngineID += 1
        var chosen: Int?
        for offset in 0..<255 {
            let candidate = ((asidCursor - 1 + offset) % 255) + 1
            if asidRefCount[candidate] == 0 {
                chosen = candidate
                break
            }
        }
        let asid = chosen ?? asidCursor
        asidCursor = (asid % 255) + 1
        asidRefCount[asid] += 1
        return (id, UInt8(asid))
    }

    func releaseASID(_ asid: UInt8) {
        let index = Int(asid)
        if asidRefCount[index] > 0 { asidRefCount[index] -= 1 }
    }

    func allocateSlab(size: Int) throws -> Slab {
        try Slab.allocate(size: size, from: ipaAllocator)
    }

    func releaseSlab(_ slab: Slab) {
        slab.release(to: ipaAllocator)
    }

    func hvCheck(_ code: hv_return_t, _ context: String) throws {
        if code != HV_SUCCESS {
            throw AnisetteError("Hypervisor \(context) failed: \(Self.formatStatus(code))")
        }
    }

    func activate(_ engine: HypervisorEngine) throws {
        if activeEngine === engine {
            if engine.needsTLBFlush {
                try invalidateTLB(restoring: engine)
                engine.needsTLBFlush = false
            }
            return
        }
        if let previous = activeEngine {
            try previous.saveFromVCPU(self)
        }
        let needsFlush = engine.needsTLBFlush || lastASIDOwner[Int(engine.asid)] != engine.id
        try engine.loadIntoVCPU(self)
        if needsFlush {
            try invalidateTLB(restoring: engine)
            lastASIDOwner[Int(engine.asid)] = engine.id
            engine.needsTLBFlush = false
        }
        activeEngine = engine
    }

    private func invalidateTLB(restoring engine: HypervisorEngine) throws {
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
        try hvCheck(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_TTBR0_EL1, engine.ttbr0), "restore TTBR0 after TLBI")
        try hvCheck(hv_vcpu_set_reg(vcpu, HV_REG_PC, savedPC), "restore PC after TLBI")
    }

    func runSingleStep(cancellation: Cancellation, deadlineCval: UInt64?) throws -> hv_vcpu_exit_t {
        if let deadlineCval {
            let now = mach_absolute_time() &- vtimerOffset
            if now >= deadlineCval { throw AnisetteError("Guest execution timed out") }
            try hvCheck(hv_vcpu_set_sys_reg(vcpu, HV_SYS_REG_CNTV_CVAL_EL0, deadlineCval), "set CNTV_CVAL_EL0")
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
        return exitPointer.pointee
    }

    func readReg(_ reg: hv_reg_t) throws -> UInt64 {
        var value: UInt64 = 0
        try hvCheck(hv_vcpu_get_reg(vcpu, reg, &value), "read register \(reg.rawValue)")
        return value
    }

    func writeReg(_ reg: hv_reg_t, _ value: UInt64) throws {
        try hvCheck(hv_vcpu_set_reg(vcpu, reg, value), "write register \(reg.rawValue)")
    }

    func readSysReg(_ reg: hv_sys_reg_t) throws -> UInt64 {
        var value: UInt64 = 0
        try hvCheck(hv_vcpu_get_sys_reg(vcpu, reg, &value), "read sysreg 0x\(String(reg.rawValue, radix: 16))")
        return value
    }

    func writeSysReg(_ reg: hv_sys_reg_t, _ value: UInt64) throws {
        try hvCheck(hv_vcpu_set_sys_reg(vcpu, reg, value), "write sysreg 0x\(String(reg.rawValue, radix: 16))")
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
