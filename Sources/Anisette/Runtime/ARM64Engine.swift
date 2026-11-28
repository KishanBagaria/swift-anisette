#if arch(arm64) && (os(macOS) || os(Linux))
import Foundation

/// Why a single vCPU run returned to `ARM64Engine`.
enum ARM64Exit {
    /// A kick or timer exit before the deadline expired.
    case interrupted
    /// A trap instruction (`HVC`/`BRK`) with immediate `imm` at guest address `address`.
    case trap(imm: UInt64, address: UInt64)
}

/// Process-wide single-vCPU VM (Hypervisor.framework or KVM) confined to its worker thread.
protocol ARM64VCPU: AnyObject {
    associatedtype Slab: GuestSlab
    associatedtype Deadline

    /// Trap instructions with immediates 0 (service call), 1 (return), and 0xffff (exception vector).
    static var serviceTrap: UInt32 { get }
    static var returnTrap: UInt32 { get }
    static var vectorTrap: UInt32 { get }
    static var trapMnemonic: String { get }
    /// Whether the vCPU PC already points past the trap instruction on a trap exit.
    static var trapAdvancesPC: Bool { get }
    static func invalidateICache(_ address: UnsafeMutableRawPointer, _ size: Int)

    var asidAllocator: ASIDAllocator { get }
    var ipaAllocator: IPAAllocator { get }
    var activeEngine: ARM64Engine<Self>? { get set }
    var isCurrentThread: Bool { get }
    func performSync<T>(_ body: () throws -> T) throws -> T
    /// Forces a running vCPU to exit; safe from any thread.
    func requestExit()
    func allocateSlab(size: Int) throws -> Slab
    func releaseSlab(_ slab: Slab)
    func read(_ reg: ARM64Register) throws -> UInt64
    func write(_ reg: ARM64Register, _ value: UInt64) throws
    func readSIMD(_ index: Int) throws -> Data
    func writeSIMD(_ index: Int, _ data: Data) throws
    /// Invalidates all EL1 TLB entries, leaving the vCPU on `ttbr0` with its PC unchanged.
    func invalidateTLB(restoringTTBR0 ttbr0: UInt64) throws
    func deadline(afterMicroseconds timeout: UInt64) -> Deadline
    /// Runs `body` with `deadline` armed, restoring any enclosing deadline afterwards.
    func withDeadline<T>(_ deadline: Deadline?, _ body: () throws -> T) throws -> T
    /// Runs the vCPU until its next exit; throws on timeout, cancellation, or an unexpected exit.
    func run(cancellation: Cancellation, deadline: Deadline?) throws -> ARM64Exit
}

extension ARM64VCPU {
    var userAllocatedIPABytes: UInt64 {
        (try? performSync {
            let total = ipaAllocator.allocatedBytes
            let trampolineBytes = ARM64.ipaSlabSize * 2
            return total >= trampolineBytes ? total - trampolineBytes : 0
        }) ?? 0
    }

    var liveEngineCount: Int {
        (try? performSync { asidAllocator.liveCount }) ?? 0
    }

    var ipaHighWaterMark: UInt64 {
        (try? performSync { ipaAllocator.highWaterMark }) ?? 0
    }

    /// Switches the vCPU to `engine`, flushing the TLB when its ASID was last used by another engine.
    func activate(_ engine: ARM64Engine<Self>) throws {
        if activeEngine === engine {
            if engine.needsTLBFlush {
                try invalidateTLB(restoringTTBR0: engine.ttbr0)
                engine.needsTLBFlush = false
            }
            return
        }
        try activeEngine?.saveFromVCPU()
        let needsFlush = engine.needsTLBFlush || asidAllocator.needsFlush(for: engine.asid, engineID: engine.id)
        try engine.loadIntoVCPU()
        if needsFlush {
            try invalidateTLB(restoringTTBR0: engine.ttbr0)
            asidAllocator.markOwner(asid: engine.asid, engineID: engine.id)
            engine.needsTLBFlush = false
        }
        activeEngine = engine
    }
}

/// Guest engine running EL1 code natively on a shared `ARM64VCPU`, context-switching registers between engines.
final class ARM64Engine<VCPU: ARM64VCPU>: GuestEngine {
    let runtime: VCPU
    let cancellation: Cancellation
    let id: UInt64
    let asid: UInt8
    let ttbr0: UInt64
    var emulatesUnsupportedInstructions: Bool { lastFaultWasUndefinedInstruction }
    var needsTLBFlush = false

    private var registers = RegisterSnapshot()
    private let addressSpace: GuestAddressSpace<VCPU.Slab>
    private var serviceRange: Range<UInt64>?
    private var serviceHandler: ((UInt64) -> Void)?
    private let stopLock = NSLock()
    private var stopped = false
    private var hasExecuted = false
    private var lastFaultWasUndefinedInstruction = false

    init(runtime: VCPU, cancellation: Cancellation) throws {
        self.runtime = runtime
        self.cancellation = cancellation
        let (identity, space) = try runtime.performSync {
            let identity = runtime.asidAllocator.allocate()
            do {
                let space = try GuestAddressSpace(
                    allocateSlab: runtime.allocateSlab,
                    releaseSlab: runtime.releaseSlab,
                    invalidateICache: VCPU.invalidateICache,
                    vectorTrapInstruction: VCPU.vectorTrap
                )
                return (identity, space)
            } catch {
                runtime.asidAllocator.release(identity.asid)
                throw error
            }
        }
        self.id = identity.id
        self.asid = identity.asid
        self.addressSpace = space
        self.ttbr0 = space.l0IPA | (UInt64(identity.asid) << 48)
    }

    deinit {
        let space = addressSpace
        let asidToFree = asid
        let runtime = runtime
        // `activeEngine` is weak, so it already reads nil here.
        try? runtime.performSync {
            space.reclaim()
            runtime.asidAllocator.release(asidToFree)
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
                    VCPU.invalidateICache(segment.host, segment.count)
                    offset += segment.count
                }
            }
        }
    }

    private static func location(of reg: GuestRegister) throws
        -> (register: ARM64Register, snapshot: WritableKeyPath<RegisterSnapshot, UInt64>) {
        switch reg {
        case .x(let index):
            try require((0...30).contains(index), "Invalid guest register x\(index)")
            return (.x(index), \.x[index])
        case .sp: return (.spEL1, \.spEL1)
        case .pc: return (.pc, \.pc)
        }
    }

    func register(_ reg: GuestRegister) throws -> UInt64 {
        let (register, snapshot) = try Self.location(of: reg)
        return try runtime.performSync {
            runtime.activeEngine === self ? try runtime.read(register) : registers[keyPath: snapshot]
        }
    }

    func register(_ reg: GuestRegister, _ value: UInt64) throws {
        let (register, snapshot) = try Self.location(of: reg)
        try runtime.performSync {
            if runtime.activeEngine === self { try runtime.write(register, value) } else { registers[keyPath: snapshot] = value }
        }
    }

    func vector(_ index: Int) throws -> Data {
        try require((0...31).contains(index), "Invalid guest vector register v\(index)")
        return try runtime.performSync {
            runtime.activeEngine === self ? try runtime.readSIMD(index) : registers.q[index]
        }
    }

    func vector(_ index: Int, _ data: Data) throws {
        try require((0...31).contains(index), "Invalid guest vector register v\(index)")
        try require(data.count == 16, "Invalid vector register width")
        try runtime.performSync {
            if runtime.activeEngine === self { try runtime.writeSIMD(index, data) } else { registers.q[index] = data }
        }
    }

    func writeReturnTrap(at address: UInt64) throws {
        try write(address, VCPU.returnTrap)
    }

    func installServiceStub(at address: UInt64) throws {
        try write(address, Data.littleEndian(VCPU.serviceTrap) + Data.littleEndian(ARM64.ret))
    }

    func installServiceDispatcher(range: Range<UInt64>, handler: @escaping (UInt64) -> Void) throws {
        try require(!range.isEmpty, "Invalid guest service range")
        try runtime.performSync {
            serviceRange = range
            serviceHandler = handler
        }
    }

    func start(_ begin: UInt64, until end: UInt64, timeout: UInt64) throws {
        lastFaultWasUndefinedInstruction = false
        try cancellation.check()
        try runtime.performSync {
            setStopped(false)
            hasExecuted = true
            try register(.pc, begin)
            let deadline = timeout > 0 ? runtime.deadline(afterMicroseconds: timeout) : nil
            try runtime.withDeadline(deadline) { try runLoop(until: end, deadline: deadline) }
        }
    }

    private func runLoop(until end: UInt64, deadline: VCPU.Deadline?) throws {
        while true {
            try cancellation.check()
            try runtime.activate(self)
            switch try runtime.run(cancellation: cancellation, deadline: deadline) {
            case .interrupted:
                if isStopped() { return }
            case .trap(let imm, let address):
                if try handleTrap(imm: imm, at: address, until: end) { return }
            }
        }
    }

    private func handleTrap(imm: UInt64, at address: UInt64, until end: UInt64) throws -> Bool {
        let mnemonic = VCPU.trapMnemonic
        switch imm {
        case 0:
            guard let range = serviceRange, range.contains(address), let handler = serviceHandler else {
                throw AnisetteError("Unexpected \(mnemonic) #0 at 0x\(String(address, radix: 16))")
            }
            // Point PC at the stub's trailing RET before invoking the handler so
            // handlers like `dispatchOnce`/`pthreadOnce` can redirect PC without being overwritten.
            if !VCPU.trapAdvancesPC { try runtime.write(.pc, address &+ 4) }
            setStopped(false)
            handler(address)
            try cancellation.check()
            return isStopped()
        case 1:
            guard address == end else {
                throw AnisetteError("Unexpected \(mnemonic) #1 at 0x\(String(address, radix: 16))")
            }
            if VCPU.trapAdvancesPC { try runtime.write(.pc, address) }
            return true
        case 0xffff:
            let elr = try runtime.read(.elrEL1)
            let esr = try runtime.read(.esrEL1)
            let far = try runtime.read(.farEL1)
            let spsr = try runtime.read(.spsrEL1)
            lastFaultWasUndefinedInstruction = ((esr >> 26) & 0x3f) == 0
            try runtime.write(.pc, elr)
            if lastFaultWasUndefinedInstruction {
                try runtime.write(.cpsr, spsr)
            }
            throw AnisetteError(
                "Guest exception ELR=0x\(String(elr, radix: 16)) ESR=0x\(String(esr, radix: 16)) FAR=0x\(String(far, radix: 16))"
            )
        default:
            throw AnisetteError("Unexpected \(mnemonic) #0x\(String(imm, radix: 16)) at 0x\(String(address, radix: 16))")
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

    func saveFromVCPU() throws {
        for index in 0..<31 {
            registers.x[index] = try runtime.read(.x(index))
        }
        for index in 0..<32 {
            registers.q[index] = try runtime.readSIMD(index)
        }
        for (reg, path) in RegisterSnapshot.contextRegisters {
            registers[keyPath: path] = try runtime.read(reg)
        }
    }

    func loadIntoVCPU() throws {
        try runtime.write(.ttbr0EL1, ttbr0)
        try runtime.write(.vbarEL1, ARM64.vbarGuestVA)
        for (reg, path) in RegisterSnapshot.contextRegisters {
            try runtime.write(reg, registers[keyPath: path])
        }
        for index in 0..<31 {
            try runtime.write(.x(index), registers.x[index])
        }
        for index in 0..<32 {
            try runtime.writeSIMD(index, registers.q[index])
        }
    }
}

#if os(macOS)
typealias NativeRuntime = HypervisorRuntime
#else
typealias NativeRuntime = KVMRuntime
#endif
#endif
