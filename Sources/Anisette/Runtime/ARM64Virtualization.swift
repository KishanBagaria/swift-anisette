import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#endif

/// Architectural constants and encoding helpers shared by ARM64 bare-metal EL1 hypervisor backends.
enum ARM64 {
    static let guestPageSize: UInt64 = 4096
    static let ipaSlabSize: UInt64 = 16384
    static let maxGuestVA: UInt64 = 0x8000_0000_0000
    static let vbarGuestVA: UInt64 = 0x8000_0000_0000
    static let trampolineVA: UInt64 = 0x8000_0001_0000
    static let ipaBase: UInt64 = 0x4000_0000
    /// Size of the slab holding the TLBI trampoline's page tables and code.
    static let trampolineSlabSize = ipaSlabSize * 2

    static func hvc(_ imm: UInt16) -> UInt32 { 0xd4000002 | UInt32(imm) << 5 }
    static func brk(_ imm: UInt16) -> UInt32 { 0xd4200000 | UInt32(imm) << 5 }

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
    static let ecBRK64: UInt64 = 0x3c

    /// Physical address bits for each `TCR_EL1.IPS` encoding (`0...5`).
    static let paBitsByIPS = [32, 36, 40, 42, 44, 48]

    /// Computes `TCR_EL1` and the usable IPA upper bound from host IPA width and `ID_AA64MMFR0_EL1`.
    /// Returns `nil` if 4 KiB Stage-1 translation granule is unsupported or IPA space is too small.
    static func stage1Configuration(ipaBits: Int, mmfr0: UInt64) -> (tcr: UInt64, ipaLimit: UInt64)? {
        guard (mmfr0 >> 28) & 0xf != 0xf else { return nil }
        let paRange = min(Int(mmfr0 & 0xf), paBitsByIPS.count - 1)
        let requestedIPS = paBitsByIPS.firstIndex { $0 >= ipaBits } ?? (paBitsByIPS.count - 1)
        let ips = min(requestedIPS, paRange)
        let effectiveIPABits = min(ipaBits, paBitsByIPS[ips])
        let ipaLimit = effectiveIPABits >= 63 ? UInt64.max : (UInt64(1) << effectiveIPABits)
        guard ipaBase < ipaLimit else { return nil }
        // T0SZ=16 (48-bit VA), IRGN0=1, ORGN0=1, SH0=3, TG0=0 (4 KiB), EPD1=1, TG1=2, IPS=ips
        let tcr: UInt64 = 16 | (1 << 8) | (1 << 10) | (3 << 12) | (1 << 23) | (2 << 30) | (UInt64(ips) << 32)
        return (tcr, ipaLimit)
    }

    /// Populates a `trampolineSlabSize` slab with an ASID=0 4-level page table + EL1 TLBI trampoline at `ARM64.trampolineVA`.
    static func writeTLBITrampoline<Slab: GuestSlab>(
        into slab: Slab,
        trapInstruction: UInt32,
        invalidateICache: (UnsafeMutableRawPointer, Int) -> Void
    ) -> UInt64 {
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

        let code: [UInt32] = [ARM64.tlbiVMALLE1, ARM64.dsbSY, ARM64.isb, trapInstruction]
        for (index, word) in code.enumerated() {
            hostPtr.storeBytes(of: word.littleEndian, toByteOffset: 0x4000 + index * 4, as: UInt32.self)
        }
        invalidateICache(hostPtr.advanced(by: 0x4000), Int(ARM64.guestPageSize))
        return ipa // ASID = 0
    }
}

/// Architectural registers a vCPU backend exposes to `ARM64Engine`.
enum ARM64Register: Hashable, Sendable {
    case x(Int)
    case spEL0, spEL1, pc, cpsr, fpcr, fpsr
    case elrEL1, spsrEL1, esrEL1, farEL1
    case tpidrEL0, tpidrROEL0, tpidrEL1, contextidrEL1
    case ttbr0EL1
}

/// Snapshot of guest architectural registers preserved across vCPU context switches.
struct RegisterSnapshot {
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

    /// Registers saved and restored on a context switch, besides x0-x30 and q0-q31.
    nonisolated(unsafe) static let contextRegisters: [(ARM64Register, WritableKeyPath<RegisterSnapshot, UInt64>)] = [
        (.spEL1, \.spEL1), (.spEL0, \.spEL0), (.pc, \.pc), (.cpsr, \.cpsr), (.fpcr, \.fpcr), (.fpsr, \.fpsr),
        (.tpidrEL0, \.tpidrEL0), (.tpidrROEL0, \.tpidrROEL0), (.tpidrEL1, \.tpidrEL1),
        (.elrEL1, \.elrEL1), (.esrEL1, \.esrEL1), (.farEL1, \.farEL1),
        (.spsrEL1, \.spsrEL1), (.contextidrEL1, \.contextidrEL1),
    ]
}

/// Tracks 8-bit ASID assignment (`1...255`, reserving `0` for the permanent TLBI trampoline) and reuse.
final class ASIDAllocator {
    private var nextEngineID: UInt64 = 1
    private var cursor: Int = 1
    private var refCount = [Int](repeating: 0, count: 256)
    private var lastOwner = [UInt64](repeating: 0, count: 256)

    func allocate() -> (id: UInt64, asid: UInt8) {
        let id = nextEngineID
        nextEngineID += 1
        var chosen: Int?
        for offset in 0..<255 {
            let candidate = ((cursor - 1 + offset) % 255) + 1
            if refCount[candidate] == 0 {
                chosen = candidate
                break
            }
        }
        let asid = chosen ?? cursor
        cursor = (asid % 255) + 1
        refCount[asid] += 1
        return (id, UInt8(asid))
    }

    func release(_ asid: UInt8) {
        let index = Int(asid)
        if refCount[index] > 0 { refCount[index] -= 1 }
    }

    func needsFlush(for asid: UInt8, engineID: UInt64) -> Bool {
        lastOwner[Int(asid)] != engineID
    }

    func markOwner(asid: UInt8, engineID: UInt64) {
        lastOwner[Int(asid)] = engineID
    }

    var liveCount: Int {
        refCount.reduce(0, +)
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
        try require(size <= limit && cursor <= limit - size, "Hypervisor IPA space exhausted")
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

/// Host memory slab mapped into a guest VM at a 16 KiB-aligned IPA.
protocol GuestSlab {
    var host: UnsafeMutableRawPointer { get }
    var ipa: UInt64 { get }
    var size: Int { get }
}

private struct PageTable {
    let host: UnsafeMutableRawPointer
    let ipa: UInt64
}

private struct MappedRegion {
    let vaStart: UInt64
    let vaEnd: UInt64
    let hostBase: UnsafeMutableRawPointer
}

/// Manages 16 KiB-aligned IPA slabs and 4-level 4 KiB Stage-1 page tables for one guest machine.
final class GuestAddressSpace<Slab: GuestSlab> {
    private let allocateSlabFn: (Int) throws -> Slab
    private let releaseSlabFn: (Slab) -> Void
    private let invalidateICacheFn: (UnsafeMutableRawPointer, Int) -> Void
    private var slabs: [Slab] = []
    private var freeSubPages: [PageTable] = []
    private var regions: [MappedRegion] = []
    private var tablesByIPA: [UInt64: UnsafeMutableRawPointer] = [:]
    private let l0Table: PageTable
    var l0IPA: UInt64 { l0Table.ipa }

    init(
        allocateSlab: @escaping (Int) throws -> Slab,
        releaseSlab: @escaping (Slab) -> Void,
        invalidateICache: @escaping (UnsafeMutableRawPointer, Int) -> Void,
        vectorTrapInstruction: UInt32
    ) throws {
        self.allocateSlabFn = allocateSlab
        self.releaseSlabFn = releaseSlab
        self.invalidateICacheFn = invalidateICache
        let slab = try allocateSlab(Int(ARM64.ipaSlabSize))
        slabs.append(slab)
        freeSubPages += Self.pages(in: slab, from: 1).reversed()
        l0Table = PageTable(host: slab.host, ipa: slab.ipa)
        tablesByIPA[l0Table.ipa] = l0Table.host
        do { try installVectorTable(trapInstruction: vectorTrapInstruction) } catch { reclaim(); throw error }
    }

    func reclaim() {
        slabs.forEach(releaseSlabFn)
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
        let slab = try allocateSlabFn(Int(ARM64.ipaSlabSize))
        slabs.append(slab)
        freeSubPages += Self.pages(in: slab, from: 1).reversed()
        return PageTable(host: slab.host, ipa: slab.ipa)
    }

    private func installVectorTable(trapInstruction: UInt32) throws {
        let vbarPage = try allocateSubPage()
        for offset in stride(from: 0, to: 2048, by: 4) {
            vbarPage.host.storeBytes(of: trapInstruction.littleEndian, toByteOffset: offset, as: UInt32.self)
        }
        invalidateICacheFn(vbarPage.host, Int(ARM64.guestPageSize))
        try mapPage(va: ARM64.vbarGuestVA, ipa: vbarPage.ipa, descriptorBits: ARM64.roPageDescriptorBits)
    }

    private func ensureChildTable(in parent: PageTable, index: Int) throws -> PageTable {
        let entryOffset = index * 8
        let current = UInt64(littleEndian: parent.host.load(fromByteOffset: entryOffset, as: UInt64.self))
        if current & 0x3 == 0x3 {
            let nextIPA = current & 0x0000_ffff_ffff_f000
            guard let nextHost = tablesByIPA[nextIPA] else {
                throw AnisetteError("Missing guest page table at 0x\(String(nextIPA, radix: 16))")
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
        try mapContiguousPages(vaStart: va, ipaStart: ipa, pageCount: 1, descriptorBits: descriptorBits)
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
        let index = firstRegionIndex(endingAfter: address)
        return index < regions.count && regions[index].vaStart <= address ? regions[index] : nil
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
        let slab = try allocateSlabFn(Int(try guestAligned(size, to: ARM64.ipaSlabSize)))
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

/// Dedicated POSIX thread for thread-bound vCPU execution (`Hypervisor.framework` and Linux KVM).
final class GuestWorkerThread: @unchecked Sendable {
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

    private let name: String
    private let queueCondition = NSCondition()
    private var pendingJobs: [() -> Void] = []
    /// Set by the thread itself before `init` returns.
    private var thread: pthread_t?
    private let readySemaphore = DispatchSemaphore(value: 0)

    init(name: String) {
        self.name = name
        var attributes = pthread_attr_t()
        pthread_attr_init(&attributes)
        pthread_attr_setstacksize(&attributes, 2 << 20)
        let context = Unmanaged.passUnretained(self).toOpaque()
        #if canImport(Darwin)
        var created: pthread_t?
        #else
        var created: pthread_t = 0
        #endif
        let rc = pthread_create(&created, &attributes, { GuestWorkerThread.threadMain($0) }, context)
        pthread_attr_destroy(&attributes)
        precondition(rc == 0, "Cannot create guest worker thread (\(rc))")
        readySemaphore.wait()
    }

    var handle: pthread_t { thread! }

    private static func threadMain(_ context: UnsafeMutableRawPointer?) -> UnsafeMutableRawPointer? {
        guard let context else { return nil }
        Unmanaged<GuestWorkerThread>.fromOpaque(context).takeUnretainedValue().runLoop()
        return nil
    }

    var isCurrentThread: Bool {
        guard let thread else { return false }
        return pthread_equal(pthread_self(), thread) != 0
    }

    private func runLoop() {
        #if canImport(Darwin)
        pthread_setname_np(name)
        #else
        pthread_setname_np(pthread_self(), String(name.prefix(15)))
        #endif
        thread = pthread_self()
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
                throw AnisetteError("Guest worker thread failed to produce a result")
            }
            return try result.get()
        }
    }
}
