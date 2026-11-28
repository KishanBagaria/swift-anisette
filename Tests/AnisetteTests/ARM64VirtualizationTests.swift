#if os(macOS) || os(Linux)
import Foundation
import Testing
@testable import Anisette

/// Shared ARM64 virtualization helpers, plus guest execution on this host's native backend
/// (Hypervisor.framework on macOS, KVM on Linux) when it is available.
@Suite(.serialized)
struct ARM64VirtualizationTests {
    private static let environment = AnisetteTests.environment

    private static var hasNativeBackend: Bool { Resources.nativeBackend.map(Resources.isAvailable) ?? false }

    @Test func explicitBackendResolutionAndFallbackBehavior() throws {
        #expect(try Resources.resolveBackend(.unicorn) == .unicorn)
        #expect(try Resources.resolveBackend(.automatic) == (Self.hasNativeBackend ? Resources.nativeBackend : .unicorn))
        let explicit: [(AnisetteConfiguration.Backend, Resources.ExecutionBackend, String)] = [
            (.hypervisor, .hypervisor, "Hypervisor"), (.kvm, .kvm, "KVM"),
        ]
        for (requested, backend, name) in explicit {
            if Self.hasNativeBackend, backend == Resources.nativeBackend {
                #expect(try Resources.resolveBackend(requested) == backend)
            } else {
                let error = #expect(throws: AnisetteError.self) {
                    _ = try Resources.resolveBackend(requested)
                }
                #expect(error?.description.contains(name) == true)
            }
        }
    }

    @Test(arguments: [(AnisetteConfiguration.Backend.hypervisor, "Hypervisor"), (.kvm, "KVM")])
    func explicitNativeBackendFailsWithoutNetworkWhenUnavailable(backend: AnisetteConfiguration.Backend, name: String) async {
        guard (try? Resources.resolveBackend(backend)) == nil else { return }
        let missingAssets = FileManager.default.temporaryDirectory
            .appendingPathComponent("anisette-native-missing-\(UUID().uuidString)")
        let config = AnisetteConfiguration(
            appleDirectory: missingAssets,
            httpClient: AnisetteTests.offline,
            backend: backend
        )
        let error = await #expect(throws: AnisetteError.self) {
            try await AnisetteContext.prepare(configuration: config)
        }
        #expect(error?.description.contains(name) == true)
    }

    @Test func ipaAllocatorCoalescesReusesAndReclaimsToZero() throws {
        let allocator = IPAAllocator(base: 0x4000_0000, limit: 0x1_0000_0000)
        let a = try allocator.allocate(16384)
        let b = try allocator.allocate(32768)
        let c = try allocator.allocate(16384)
        #expect(allocator.allocatedBytes == 65536)
        allocator.release(a..<a + 16384)
        allocator.release(c..<c + 16384)
        allocator.release(b..<b + 32768)
        #expect(allocator.allocatedBytes == 0)
        #expect(allocator.highWaterMark == 0)

        for _ in 0..<300 {
            let slab = try allocator.allocate(65536)
            #expect(slab == 0x4000_0000)
            allocator.release(slab..<slab + 65536)
        }
        #expect(allocator.allocatedBytes == 0)
        #expect(allocator.highWaterMark == 0)
    }

    @Test func ipaAllocatorRejectsInvalidSizesAndExhaustion() throws {
        let allocator = IPAAllocator(base: 0x4000_0000, limit: 0x4001_0000)
        #expect(throws: AnisetteError.self) { _ = try allocator.allocate(0) }
        #expect(throws: AnisetteError.self) { _ = try allocator.allocate(4096) }
        let first = try allocator.allocate(32768)
        let second = try allocator.allocate(32768)
        #expect(first == 0x4000_0000)
        #expect(second == 0x4000_8000)
        #expect(throws: AnisetteError.self) { _ = try allocator.allocate(16384) }
        allocator.release(first..<first + 32768)
        let reused = try allocator.allocate(16384)
        #expect(reused == first)
        #expect(allocator.allocatedBytes == 49152)
    }

    @Test func asidAllocatorWrapsAndTracksLastOwner() {
        let pool = ASIDAllocator()
        var firstPass: [(id: UInt64, asid: UInt8)] = []
        for _ in 0..<255 {
            let identity = pool.allocate()
            #expect(identity.asid != 0)
            #expect(pool.needsFlush(for: identity.asid, engineID: identity.id))
            pool.markOwner(asid: identity.asid, engineID: identity.id)
            #expect(!pool.needsFlush(for: identity.asid, engineID: identity.id))
            firstPass.append(identity)
        }
        #expect(Set(firstPass.map(\.asid)).count == 255)
        #expect(pool.liveCount == 255)

        pool.release(firstPass[0].asid)
        #expect(pool.liveCount == 254)
        let reused = pool.allocate()
        #expect(reused.asid == firstPass[0].asid)
        #expect(pool.needsFlush(for: reused.asid, engineID: reused.id))
        pool.markOwner(asid: reused.asid, engineID: reused.id)
        #expect(!pool.needsFlush(for: reused.asid, engineID: reused.id))
    }

    @Test func arm64Stage1ConfigurationComputesTCRAndRejectsUnsupportedGranule() throws {
        // PARange=5 (48-bit PA), TGran4=0 (4 KiB supported)
        let mmfr0Full: UInt64 = 5
        let config40 = try #require(ARM64.stage1Configuration(ipaBits: 40, mmfr0: mmfr0Full))
        #expect(config40.ipaLimit == (UInt64(1) << 40))
        #expect((config40.tcr >> 32) & 0x7 == 2) // IPS=2 (40-bit)

        // Clamp IPS when hardware PARange (1 -> 36-bit) is smaller than requested IPA (48-bit).
        let mmfr0SmallPA: UInt64 = 1
        let configClamped = try #require(ARM64.stage1Configuration(ipaBits: 48, mmfr0: mmfr0SmallPA))
        #expect(configClamped.ipaLimit == (UInt64(1) << 36))
        #expect((configClamped.tcr >> 32) & 0x7 == 1) // IPS=1 (36-bit)

        // TGran4 = 0xf means 4 KiB Stage-1 granule unsupported.
        let mmfr0No4K: UInt64 = (0xf << 28) | 5
        #expect(ARM64.stage1Configuration(ipaBits: 40, mmfr0: mmfr0No4K) == nil)
    }

    #if arch(arm64) && (os(macOS) || os(Linux))
    private static var nativeConfigurationBackend: AnisetteConfiguration.Backend {
        Resources.nativeBackend == .kvm ? .kvm : .hypervisor
    }

    static func makeMachine(
        imports: [String: UInt64] = [:],
        cancellation: Cancellation? = nil,
        pauseRunLoop: Bool = false
    ) throws -> GuestMachine {
        let cancel = try cancellation ?? Cancellation()
        let engine = try ARM64Engine(runtime: try NativeRuntime.shared(), cancellation: cancel)
        return try GuestMachine(name: "test", profile: try .synthetic(imports: imports), engine: engine,
                                pauseRunLoop: pauseRunLoop)
    }

    @Test(.enabled(if: hasNativeBackend))
    func nativeBackendSkipsUnicornDownloadWhenActive() async throws {
        let missingAssets = FileManager.default.temporaryDirectory
            .appendingPathComponent("anisette-native-no-unicorn-\(UUID().uuidString)")
        let requestedUnicorn = Flag()
        let config = AnisetteConfiguration(
            appleDirectory: missingAssets,
            httpClient: AnisetteHTTPClient { url, _ in
                if url == UnicornArtifact.current.url { await requestedUnicorn.set() }
                throw AnisetteError("Offline test")
            },
            backend: .automatic
        )
        await #expect(throws: AnisetteError.self) {
            _ = try await Resources.load(configuration: config)
        }
        #expect(!(await requestedUnicorn.value))

        if let appleDir = Self.environment["ANISETTE_APPLE_DIR"] {
            let offlineConfig = AnisetteConfiguration(
                appleDirectory: URL(fileURLWithPath: appleDir),
                httpClient: AnisetteTests.offline,
                backend: .automatic
            )
            let resources = try await Resources.load(configuration: offlineConfig)
            #expect(resources.engine == (try Resources.Engine(#require(Resources.nativeBackend), unicornLibrary: nil)))
        }
    }

    @Test(.enabled(if: hasNativeBackend))
    func executes4KiBPagesHighVAsSIMDFaultsAndICache() throws {
        let machine = try Self.makeMachine()
        let codePage0: UInt64 = 0x180001000 // Non-16 KiB aligned 4 KiB page
        let codePage1: UInt64 = 0x180002000
        let highDataPage: UInt64 = 0x7ff8_7000_1000 // Near 47-bit guest VA ceiling
        try machine.engine.map(codePage0, 4096)
        try machine.engine.map(codePage1, 4096)
        try machine.engine.map(highDataPage, 4096)

        // Cross-page execution & cross-page data access + FP/SIMD (FADD D0, D0, D1).
        // Put `MOVZ X0, #0x42` at end of codePage0 (0x180001ffc), `RET` at start of codePage1 (0x180002000).
        try machine.engine.write(0x180001ffc, UInt32(0xd2800840)) // mov x0, #0x42
        try machine.engine.write(0x180002000, UInt32(0xd65f03c0)) // ret
        #expect(try machine.invoke(0x180001ffc) == 0x42)

        // Cross-page data read/write across codePage0/codePage1 boundary.
        let payload = Data([0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80])
        try machine.engine.write(0x180001ffc, payload)
        #expect(try machine.engine.read(0x180001ffc, 8) == payload)

        // FP/SIMD executes natively without trapping (CPACR_EL1.FPEN = 0b11):
        // FADD V0.4S, V1.4S, V2.4S (0x4e22d420), RET (0xd65f03c0)
        try machine.engine.write(highDataPage, Data.littleEndian(UInt32(0x4e22d420)) + Data.littleEndian(UInt32(0xd65f03c0)))
        var v1 = Data()
        var v2 = Data()
        var expected = Data()
        for index in 0..<4 {
            let a = Float(index + 1)
            let b = Float(index * 2 + 10)
            v1.append(.littleEndian(a.bitPattern))
            v2.append(.littleEndian(b.bitPattern))
            expected.append(.littleEndian((a + b).bitPattern))
        }
        try machine.engine.vector(1, v1)
        try machine.engine.vector(2, v2)
        _ = try machine.invoke(highDataPage)
        #expect(try machine.engine.vector(0) == expected)

        // Instruction cache coherency: overwrite executable page and re-execute at exact same VA.
        let icacheVA = highDataPage + 0x100
        try machine.engine.write(icacheVA, Data.littleEndian(UInt32(0xd2822220)) + Data.littleEndian(UInt32(0xd65f03c0)))
        #expect(try machine.invoke(icacheVA) == 0x1111)
        try machine.engine.write(icacheVA, Data.littleEndian(UInt32(0xd2844440)) + Data.littleEndian(UInt32(0xd65f03c0)))
        #expect(try machine.invoke(icacheVA) == 0x2222)

        // Unexpected guest fault vectors through VBAR_EL1 (trap #0xFFFF) and reports ELR/ESR/FAR.
        let faultVA = highDataPage + 0x200
        try machine.engine.write(faultVA, UInt32(0xf9400000)) // ldr x0, [x0]
        let error = #expect(throws: AnisetteError.self) {
            _ = try machine.invoke(faultVA, 0x0000_00de_adbe_ef00)
        }
        let message = error?.description ?? ""
        #expect(message.contains("ELR=0x\(String(faultVA, radix: 16))"))
        #expect(message.contains("ESR=0x"))
        #expect(message.contains("FAR=0xdeadbeef00"))
        #expect(try machine.engine.register(.pc) == faultVA)
        #expect(!machine.engine.emulatesUnsupportedInstructions)

        // Undefined instruction (UDF #0) sets emulatesUnsupportedInstructions and reports ELR/ESR.
        let undefVA = highDataPage + 0x240
        try machine.engine.write(undefVA, UInt32(0x0000_0000)) // udf #0
        let undefError = #expect(throws: AnisetteError.self) {
            _ = try machine.invoke(undefVA)
        }
        #expect(undefError?.description.contains("ELR=0x\(String(undefVA, radix: 16))") == true)
        #expect(machine.engine.emulatesUnsupportedInstructions)
    }

    @Test(.enabled(if: hasNativeBackend))
    func serviceCallsOnceRedirectAndPauseRunLoop() throws {
        let mallocStub = GuestServices.base
        let freeStub = GuestServices.base + 16
        let onceStub = GuestServices.base + 32
        let runLoopStub = GuestServices.base + 48
        let abortStub = GuestServices.base + 64
        let machine = try Self.makeMachine(
            imports: [
                "_malloc": mallocStub,
                "_free": freeStub,
                "_dispatch_once": onceStub,
                "_CFRunLoopRun": runLoopStub,
                "_abort": abortStub,
            ],
            pauseRunLoop: true
        )
        let code: UInt64 = 0x210000000
        let data: UInt64 = 0x210001000
        try machine.engine.map(code, 4096)
        try machine.engine.map(data, 4096)

        // Write a dispatch_once block struct at `data + 0x100` (invoke pointer at offset 16)
        // and predicate at `data`.
        let blockTarget = code + 0x200
        let blockStruct = data + 0x100
        try machine.engine.write(data, UInt64(0))
        try machine.engine.write(blockStruct + 16, blockTarget)

        // Block target: increments [X0 + 32] (at blockStruct + 32) by 1, returns.
        // Note dispatchOnce passes blockStruct in X0.
        // ldr x1, [x0, #32] (0xf9401001)
        // add x1, x1, #1    (0x91000421)
        // str x1, [x0, #32] (0xf9001001)
        // ret               (0xd65f03c0)
        try machine.engine.write(blockStruct + 32, UInt64(0))
        let blockWords: [UInt32] = [0xf9401001, 0x91000421, 0xf9001001, 0xd65f03c0]
        try machine.engine.write(blockTarget, words: blockWords)

        // Caller at `code`:
        // stp x29, x30, [sp, #-16]! (0xa9bf7bfd)
        // mov x0, x19               (0xaa1303e0) -> predicate
        // mov x1, x20               (0xaa1403e1) -> blockStruct
        // mov x8, x21               (0xaa1503e8) -> onceStub
        // blr x8                    (0xd63f0100)
        // mov x0, x19               (0xaa1303e0) -> predicate again
        // mov x1, x20               (0xaa1403e1)
        // mov x8, x21               (0xaa1503e8)
        // blr x8                    (0xd63f0100) -> second call must skip blockTarget
        // mov x0, #64               (0xd2800800)
        // mov x8, x22               (0xaa1603e8) -> mallocStub
        // blr x8                    (0xd63f0100)
        // mov x19, x0               (0xaa0003f3) -> save malloc'd ptr
        // mov x8, x23               (0xaa1703e8) -> freeStub
        // blr x8                    (0xd63f0100)
        // mov x0, x19               (0xaa1303e0) -> return ptr
        // ldp x29, x30, [sp], #16   (0xa8c17bfd)
        // ret                       (0xd65f03c0)
        try machine.engine.register(.x(19), data)
        try machine.engine.register(.x(20), blockStruct)
        try machine.engine.register(.x(21), onceStub)
        try machine.engine.register(.x(22), mallocStub)
        try machine.engine.register(.x(23), freeStub)
        let callerWords: [UInt32] = [
            0xa9bf7bfd,
            0xaa1303e0, 0xaa1403e1, 0xaa1503e8, 0xd63f0100,
            0xaa1303e0, 0xaa1403e1, 0xaa1503e8, 0xd63f0100,
            0xd2800800, 0xaa1603e8, 0xd63f0100,
            0xaa0003f3, 0xaa1703e8, 0xd63f0100,
            0xaa1303e0, 0xa8c17bfd, 0xd65f03c0,
        ]
        try machine.engine.write(code, words: callerWords)
        let allocated = try machine.invoke(code)
        #expect(allocated == GuestMachine.heapBase)
        #expect(try machine.engine.read(blockStruct + 32, as: UInt64.self) == 1)
        #expect(machine.services.allocations.isEmpty)

        // CFRunLoopRun stops cleanly when pauseRunLoop == true.
        let loopCaller = code + 0x100
        // stp x29, x30, [sp, #-16]!; blr x0; ldp x29, x30, [sp], #16; ret
        let loopWords: [UInt32] = [0xa9bf7bfd, 0xd63f0000, 0xa8c17bfd, 0xd65f03c0]
        try machine.engine.write(loopCaller, words: loopWords)
        _ = try machine.invoke(loopCaller, runLoopStub)
        #expect(machine.services.pausedAtRunLoop)

        // Service fault inside service trap #0 propagates cleanly.
        let abortError = #expect(throws: AnisetteError.self) {
            _ = try machine.invoke(loopCaller, abortStub)
        }
        #expect(abortError?.description == "Guest aborted")
    }

    @Test(.enabled(if: hasNativeBackend))
    func nestedInvocationsPreserveRegistersAndSeparateAddressSpaces() throws {
        let stub = GuestServices.base
        let m1 = try Self.makeMachine(imports: ["_IOConnectCallStructMethod": stub])
        let m2 = try Self.makeMachine(imports: ["_mach_msg_rpc_from_kernel_proper": stub])
        let m3 = try Self.makeMachine()

        // Map the exact same guest virtual addresses in all three machines with distinct values.
        let codeVA: UInt64 = 0x220000000
        let dataVA: UInt64 = 0x220001000
        for (index, machine) in [m1, m2, m3].enumerated() {
            try machine.engine.map(codeVA, 4096)
            try machine.engine.map(dataVA, 4096)
            try machine.engine.write(dataVA, UInt64(0x100 * (index + 1)))
        }

        // m3 adds [dataVA] + arg0 + 3, clobbers Q0 and X19.
        let m3Words: [UInt32] = [0xaa0003f3, 0xaa0103e9, 0xf940012a, 0x8b130140, 0x91000c00, 0x6e201c00, 0xd65f03c0]
        try m3.engine.write(codeVA, words: m3Words)

        m2.services.machRPCHandler = { request, _ in
            let arg: UInt64 = try request.integer(at: 0)
            let result = try m3.invoke(codeVA, arg, dataVA)
            return .littleEndian(result)
        }

        // m2 sets callee-saved x19 = 0x2222, calls machMsgRPCFromKernel, and reads own [dataVA] + reply.
        let m2Words: [UInt32] = [
            0xa9bf7bfd, 0xd2844453, 0xa9bf0be1, 0xf9002020,
            0x91010020, 0xaa0203e8, 0xd2800101, 0xd2800102,
            0xd63f0100, 0xa8c10be1, 0xf9400029, 0xf940202a,
            0x8b090260, 0x8b0a0000, 0xa8c17bfd, 0xd65f03c0,
        ]
        try m2.engine.write(codeVA, words: m2Words)

        m1.services.fairPlayHandler = { indirect in
            let input: UInt64 = try indirect.integer(at: 0)
            let sum = try m2.invoke(codeVA, input, dataVA, stub)
            return (.littleEndian(sum), 0)
        }

        // m1 sets x19 = 0x1111, Q0, Z=1, calls ioConnectCallStructMethod, and checks preserved registers/memory.
        let m1Q0 = Data(repeating: 0xab, count: 16)
        try m1.engine.vector(0, m1Q0)
        let indirectBuf = try m1.scratch(Data.littleEndian(UInt64(10)))
        let inputStruct = try m1.scratch(Data.littleEndian(indirectBuf) + Data.littleEndian(UInt64(8)))
        let outputStruct = try m1.scratch(size: 16)
        let outputSize = try m1.scratch(Data.littleEndian(UInt64(16)))
        let m1Words: [UInt32] = [
            0xa9bf7bfd, 0xa9bf53f3, 0xd2822233, 0xaa0403f4,
            0xaa0003e8, 0xaa0203e4, 0xaa0303e5, 0xaa0103e2,
            0xd2800000, 0xd2800341, 0xd2800203, 0xeb1f03ff,
            0xd63f0100, 0x540000a1, 0xf9400289, 0x8b090260,
            0xa8c153f3, 0xa8c17bfd, 0xd65f03c0,
            0xd28175a0, 0xa8c153f3, 0xa8c17bfd, 0xd65f03c0,
        ]
        try m1.engine.write(codeVA, words: m1Words)
        let m1Result = try m1.invoke(codeVA, stub, inputStruct, outputStruct, outputSize, dataVA)
        #expect(m1Result == 0x1111 + 0x100)
        #expect(try m1.engine.vector(0) == m1Q0)
        #expect(try m1.engine.read(indirectBuf, as: UInt64.self) == 0x2222 + 0x200 + 0x300 + 10 + 3)
    }

    @Test(.enabled(if: hasNativeBackend))
    func cancellationAndTimeout() async throws {
        let cancellation = try Cancellation()
        let loopMachine = try Self.makeMachine(cancellation: cancellation)
        let loopVA: UInt64 = 0x230000000
        try loopMachine.engine.map(loopVA, 4096)
        try loopMachine.engine.write(loopVA, UInt32(0x14000000)) // b .

        // Cancel active vCPU execution by forcing a vCPU exit.
        let cancelTask = Task.detached {
            try? await Task.sleep(for: .milliseconds(25))
            cancellation.cancel()
        }
        let cancelStart = ContinuousClock.now
        #expect(throws: CancellationError.self) {
            try loopMachine.invoke(loopVA)
        }
        #expect(ContinuousClock.now - cancelStart < .seconds(5))
        await cancelTask.value

        // Subsequent unrelated engine must not fail from the previous cancellation's forced exit.
        let cleanMachine = try Self.makeMachine()
        let cleanVA: UInt64 = 0x230000000
        try cleanMachine.engine.map(cleanVA, 4096)
        try cleanMachine.engine.write(cleanVA, Data.littleEndian(UInt32(0xd2800fe0)) + Data.littleEndian(UInt32(0xd65f03c0)))
        #expect(try cleanMachine.invoke(cleanVA) == 0x7f)

        // Execution timeout triggers cleanly.
        let timeoutStart = ContinuousClock.now
        let timeoutError = #expect(throws: AnisetteError.self) {
            try cleanMachine.engine.write(cleanVA, UInt32(0x14000000)) // b .
            try cleanMachine.engine.start(cleanVA, until: GuestMachine.returnAddress, timeout: 40_000)
        }
        #expect(ContinuousClock.now - timeoutStart < .seconds(5))
        #expect(timeoutError?.description == "Guest execution timed out")
    }

    @Test(.enabled(if: hasNativeBackend))
    func teardownReclaimsIPAAndHandlesASIDWraparound() throws {
        let runtime = try NativeRuntime.shared()
        let codeVA: UInt64 = 0x240000000

        // Create > 255 sequential 104 MiB GuestMachines using the same guest VA to exercise both
        // 8-bit ASID wraparound + TLB invalidation and IPA/host memory reclamation.
        // Without reclamation, 270 machines would require > 28 GiB of IPA space.
        for iteration in 0..<270 {
            let machine = try Self.makeMachine()
            try machine.engine.map(codeVA, 4096)
            let expected = UInt64(0x1000 + iteration)
            let movImmediate = UInt32(0xd2800000 | ((expected & 0xffff) << 5))
            try machine.engine.write(codeVA, Data.littleEndian(movImmediate) + Data.littleEndian(UInt32(0xd65f03c0)))
            #expect(try machine.invoke(codeVA) == expected)
        }

        if runtime.liveEngineCount == 0 {
            #expect(runtime.userAllocatedIPABytes == 0)
        }
        #expect(runtime.ipaHighWaterMark < 4 << 30)
    }

    @Test(.enabled(if: hasNativeBackend && environment["ANISETTE_APPLE_DIR"] != nil))
    func multipleNativeContextsInterleaveCleanly() async throws {
        let config = AnisetteConfiguration(
            appleDirectory: URL(fileURLWithPath: try #require(Self.environment["ANISETTE_APPLE_DIR"])),
            httpClient: AnisetteTests.offline,
            backend: Self.nativeConfigurationBackend
        )
        let contextA = try await AnisetteContext.open(identifier: UUID(), configuration: config)
        let contextB = try await AnisetteContext.open(identifier: UUID(), configuration: config)

        let errA1 = await #expect(throws: AnisetteError.self) {
            _ = try await contextA.startProvisioning(challenge: Data(count: 256))
        }
        let errB1 = await #expect(throws: AnisetteError.self) { try await contextB.requestOTP() }
        let errA2 = await #expect(throws: AnisetteError.self) { try await contextA.requestOTP() }
        let errB2 = await #expect(throws: AnisetteError.self) {
            _ = try await contextB.startProvisioning(challenge: Data(count: 256))
        }

        await contextA.close()
        let errB3 = await #expect(throws: AnisetteError.self) { try await contextB.requestOTP() }
        await contextB.close()

        #expect(errA1?.adiStatus == -45031)
        #expect(errB1?.adiStatus == AnisetteError.notProvisionedStatus)
        #expect(errA2?.adiStatus == AnisetteError.notProvisionedStatus)
        #expect(errB2?.adiStatus == -45031)
        #expect(errB3?.adiStatus == AnisetteError.notProvisionedStatus)
    }
    #endif
}

private extension GuestEngine {
    func write(_ address: UInt64, words: [UInt32]) throws {
        try write(address, words.reduce(into: Data()) { $0.append(.littleEndian($1)) })
    }
}

private actor Flag {
    private(set) var value = false
    func set() { value = true }
}
#endif
