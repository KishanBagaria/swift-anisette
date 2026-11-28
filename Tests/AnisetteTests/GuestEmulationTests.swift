#if os(macOS) || os(Linux)
import Foundation
import Testing
@testable import Anisette

extension Profile {
    static func synthetic(imports: [String: UInt64] = [:]) throws -> Profile {
        let entries = Profile.Entries(
            startProvisioning: 0, endProvisioning: 0, requestOTP: 0,
            daemonMain: 0, fairPlayDaemonMain: 0,
            kernelStart: 0, kernelSetup: 0, kernelInit: 0,
            kernelMessage: 0, kernelStackProbe: 0, kernelStackProbeValue: 0
        )
        return Profile(
            system: try AnisetteSystemInfo.current(), images: [], entries: entries, imports: imports,
            exports: [:], functions: [:], slots: [:], icxs: Data("synthetic-icxs-bytes".utf8)
        )
    }
}

private extension GuestMachine {
    func call(_ handler: String, _ arguments: [UInt64]) throws -> UInt64 {
        for (index, value) in arguments.enumerated() {
            try engine.register(.x(index), value)
        }
        try services.dispatch(handler)
        return try engine.register(.x0)
    }
}

@Suite(.serialized)
struct GuestEmulationTests {
    private static let environment = AnisetteTests.environment

    private static var cachedUnicornURL: URL? {
        if let explicit = environment["ANISETTE_UNICORN_LIBRARY"] {
            let url = URL(fileURLWithPath: explicit)
            if FileManager.default.fileExists(atPath: url.path) { return url }
        }
        let cached = AnisetteConfiguration.defaultCacheDirectory
            .appendingPathComponent(UnicornArtifact.current.relativePath)
        return FileManager.default.fileExists(atPath: cached.path) ? cached : nil
    }

    private static var hasUnicorn: Bool {
        cachedUnicornURL != nil || environment["ANISETTE_APPLE_DIR"] != nil
    }

    private static var hasHypervisor: Bool { Resources.isHypervisorAvailable }

    private static var hasAnyBackend: Bool {
        hasHypervisor || hasUnicorn
    }

    private static var availableBackends: [AnisetteConfiguration.Backend] {
        var backends: [AnisetteConfiguration.Backend] = []
        if hasHypervisor { backends.append(.hypervisor) }
        if hasUnicorn { backends.append(.unicorn) }
        return backends
    }

    private static func unicornURL() async throws -> URL {
        if let cached = cachedUnicornURL { return cached }
        return try await UnicornArtifact.current.resolve(
            in: AnisetteConfiguration.defaultCacheDirectory, http: AnisetteTests.unicornOnly
        ).url
    }

    private static func syntheticMachine(backend: AnisetteConfiguration.Backend = .automatic) async throws -> GuestMachine {
        let engine: Resources.Engine = try Resources.resolveBackend(backend) == .hypervisor ? .hypervisor
            : .unicorn(try await unicornURL())
        return try GuestMachine(name: "test", profile: try .synthetic(),
                                engine: try engine.factory(cancellation: Cancellation())())
    }

    @Test func requiredImagesMapsSharedFrameworksOnlyToCommerce() {
        #expect(GuestMachine.requiredImages(for: "commerce") == ["commerce", "CoreFP", "AppleMediaServices"])
        #expect(GuestMachine.requiredImages(for: "adid") == ["adid"])
        #expect(GuestMachine.requiredImages(for: "fairplayd") == ["fairplayd"])
        #expect(GuestMachine.requiredImages(for: "FairPlayIOKit") == ["FairPlayIOKit"])
    }

    @Test func libraryOpenReportsLoaderErrorForMissingPath() {
        let missing = URL(fileURLWithPath: "/nonexistent/swift-anisette/libunicorn-missing.dylib")
        let error = #expect(throws: AnisetteError.self) { _ = try UnicornLibrary(url: missing) }
        let message = error?.description ?? ""
        #expect(message.hasPrefix("Cannot load Unicorn: "))
        #expect(!message.contains("Incompatible Unicorn library"))
    }

    @Test(.enabled(if: hasAnyBackend), arguments: availableBackends)
    func guestMemoryAllocatorCoalescingReallocAndAlignedReuse(backend: AnisetteConfiguration.Backend) async throws {
        let machine = try await Self.syntheticMachine(backend: backend)
        let services = machine.services

        // Basic allocate, top-block cursor reclamation, and free-block reuse.
        let a = try services.allocate(32)
        let b = try services.allocate(32)
        let c = try services.allocate(32)
        #expect(services.heapCursor == 96)
        try services.release(c)
        #expect(services.heapCursor == 64)
        #expect(services.freeBlocks.isEmpty)
        try services.release(a)
        #expect(services.freeBlocks == [a..<a + 32])
        let reused = try services.allocate(16)
        #expect(reused == a)
        try services.release(reused)
        try services.release(b)
        #expect(services.allocations.isEmpty)
        #expect(services.freeBlocks.isEmpty)
        #expect(services.heapCursor == 0)

        // Coalescing both left and right neighbors.
        let x = try services.allocate(32)
        let y = try services.allocate(32)
        let z = try services.allocate(32)
        let anchor = try services.allocate(32)
        try services.release(x)
        try services.release(z)
        #expect(services.freeBlocks.count == 2)
        try services.release(y)
        #expect(services.freeBlocks == [x..<anchor])
        #expect(throws: AnisetteError.self) { try services.release(y) }
        try services.release(anchor)
        #expect(services.heapCursor == 0)
        #expect(services.freeBlocks.isEmpty)

        // Realloc: grow moves data, shrink stays in place.
        let original = try services.allocate(16)
        try machine.engine.write(original, Data("0123456789abcdef".utf8))
        try machine.engine.register(.x(0), original)
        try machine.engine.register(.x(1), 64)
        #expect(try services.memoryService("realloc"))
        let grown = try machine.engine.register(.x0)
        #expect(grown != original)
        #expect(try machine.engine.read(grown, 16) == Data("0123456789abcdef".utf8))
        try machine.engine.register(.x0, grown)
        try machine.engine.register(.x(1), 24)
        #expect(try services.memoryService("realloc"))
        #expect(try machine.engine.register(.x0) == grown)
        #expect(services.allocations[grown]?.size == 24)
        try services.release(grown)
        #expect(services.heapCursor == 0)

        // Page-aligned allocation reuses a freed interior block and preserves prefix/suffix free blocks.
        let lead = try services.allocate(32)
        let big = try services.allocate(12288)
        let tail = try services.allocate(32)
        let cursorBefore = services.heapCursor
        try services.release(big)
        let aligned = try services.allocate(4096, alignment: 4096)
        #expect(aligned % 4096 == 0)
        #expect(aligned == GuestMachine.heapBase + 4096)
        #expect(services.heapCursor == cursorBefore)
        #expect(services.freeBlocks == [big..<aligned, aligned + 4096..<tail])
        try services.release(aligned)
        try services.release(lead)
        try services.release(tail)
        #expect(services.allocations.isEmpty)
        #expect(services.freeBlocks.isEmpty)
        #expect(services.heapCursor == 0)
    }

    @Test(.enabled(if: hasAnyBackend), arguments: availableBackends)
    func emulateUnsupportedInstructions(backend: AnisetteConfiguration.Backend) async throws {
        let machine = try await Self.syntheticMachine(backend: backend)
        let codeAddress: UInt64 = 0x200000000
        let dataAddress: UInt64 = 0x200001000
        try machine.engine.map(codeAddress, 4096)
        try machine.engine.map(dataAddress, 4096)
        let ret: UInt32 = 0xd65f03c0

        var nextCode = codeAddress
        func runSnippet(_ instruction: UInt32, _ arguments: UInt64...) throws -> UInt64 {
            let slot = nextCode
            nextCode += 8
            try machine.engine.write(slot, Data.littleEndian(instruction) + Data.littleEndian(ret))
            return try machine.invoke(slot, arguments: arguments)
        }

        // EOR3 V0.16B, V1.16B, V2.16B, V3.16B (0xce020c20)
        let v1 = Data(UInt8(0)..<UInt8(16))
        let v2 = Data((0..<16).map { UInt8($0 &* 3) })
        let v3 = Data((0..<16).map { UInt8(0xa5 ^ $0) })
        let expectedV0 = Data((0..<16).map { v1[$0] ^ v2[$0] ^ v3[$0] })
        try machine.engine.vector(1, v1)
        try machine.engine.vector(2, v2)
        try machine.engine.vector(3, v3)
        _ = try runSnippet(0xce020c20)
        #expect(try machine.engine.vector(0) == expectedV0)

        // CAS W0, W1, [X2] (0x88a07c41): matching then non-matching.
        try machine.engine.write(dataAddress, UInt32(0x11223344))
        let casMatched = try runSnippet(0x88a07c41, 0xdeadbeef_11223344, 0x55667788, dataAddress)
        #expect(casMatched == 0x11223344)
        #expect(try machine.engine.read(dataAddress, as: UInt32.self) == 0x55667788)

        let casMissed = try runSnippet(0x88a07c41, 0x11223344, 0x99aabbcc, dataAddress)
        #expect(casMissed == 0x55667788)
        #expect(try machine.engine.read(dataAddress, as: UInt32.self) == 0x55667788)

        // CASAL X0, X1, [X2] (0xc8e0fc41): 64-bit matching.
        try machine.engine.write(dataAddress, UInt64(0x01020304_05060708))
        let cas64 = try runSnippet(0xc8e0fc41, 0x01020304_05060708, 0x11121314_15161718, dataAddress)
        #expect(cas64 == 0x01020304_05060708)
        #expect(try machine.engine.read(dataAddress, as: UInt64.self) == 0x11121314_15161718)

        // SWP W0, W1, [X2] (0xb8208041): 32-bit atomic swap.
        try machine.engine.write(dataAddress, UInt32(0x12345678))
        _ = try runSnippet(0xb8208041, 0xdeadbeef_87654321, 0, dataAddress)
        #expect(try machine.engine.register(.x(1)) == 0x12345678)
        #expect(try machine.engine.read(dataAddress, as: UInt32.self) == 0x87654321)

        // SWPAL X0, X1, [X2] (0xf8e08041): 64-bit atomic swap.
        try machine.engine.write(dataAddress, UInt64(0xaabbccdd_eeff0011))
        _ = try runSnippet(0xf8e08041, 0x22334455_66778899, 0, dataAddress)
        #expect(try machine.engine.register(.x(1)) == 0xaabbccdd_eeff0011)
        #expect(try machine.engine.read(dataAddress, as: UInt64.self) == 0x22334455_66778899)

        // Direct emulation test for CASA, CASL, SWPA, SWPL, and unsupported opcode rejection.
        try machine.engine.write(dataAddress, UInt32(0x00000010))
        try machine.engine.write(codeAddress, UInt32(0x88e07c41)) // CASA W0, W1, [X2]
        try machine.engine.register(.pc, codeAddress)
        try machine.engine.register(.x0, 0x00000010)
        try machine.engine.register(.x(1), 0x00000020)
        try machine.engine.register(.x(2), dataAddress)
        #expect(try machine.emulateUnsupportedInstruction())
        #expect(try machine.engine.register(.pc) == codeAddress + 4)
        #expect(try machine.engine.read(dataAddress, as: UInt32.self) == 0x00000020)

        try machine.engine.write(dataAddress, UInt64(0x10203040_50607080))
        try machine.engine.write(codeAddress, UInt32(0xf8608041)) // SWPL X0, X1, [X2]
        try machine.engine.register(.pc, codeAddress)
        try machine.engine.register(.x0, 0x80706050_40302010)
        try machine.engine.register(.x(1), 0)
        try machine.engine.register(.x(2), dataAddress)
        #expect(try machine.emulateUnsupportedInstruction())
        #expect(try machine.engine.register(.x(1)) == 0x10203040_50607080)
        #expect(try machine.engine.read(dataAddress, as: UInt64.self) == 0x80706050_40302010)

        try machine.engine.write(codeAddress, UInt32(0xd503201f)) // NOP
        try machine.engine.register(.pc, codeAddress)
        #expect(try !machine.emulateUnsupportedInstruction())
    }

    @Test(.enabled(if: hasAnyBackend), arguments: availableBackends)
    func platformAndFilesTruncate32BitArgumentsAndHandleEdgeCases(backend: AnisetteConfiguration.Backend) async throws {
        let machine = try await Self.syntheticMachine(backend: backend)
        let services = machine.services
        let dirty: UInt64 = 0xdeadbeef_00000000

        func call(_ handler: String, _ arguments: UInt64...) throws -> UInt64 {
            try machine.call(handler, arguments)
        }

        // 32-bit argument truncation on platform services.
        #expect(try call("arc4randomUniform", dirty | 1) == 0)
        #expect(try call("arc4randomUniform", dirty | 5) < 5)
        #expect(try call("sysconf", dirty | 29) == 4096)
        #expect(try call("sysconf", dirty | 57) == 1)
        #expect(try call("sysconf", dirty | 200) == GuestMachine.heapSize / 4096)

        let casCell = try machine.scratch(Data.littleEndian(UInt32(42)))
        #expect(try call("compareAndSwap32", dirty | 42, dirty | 99, casCell) == 1)
        #expect(try machine.engine.read(casCell, as: UInt32.self) == 99)

        // 32-bit argument truncation and O_TRUNC on file services.
        let pathAddress = try machine.scratch(Data((ADIRuntime.statePath + "\0").utf8))
        let payloadAddress = try machine.scratch(Data("hello!".utf8))
        let readBuffer = try machine.scratch(size: 32)
        let statBuffer = try machine.scratch(size: 144)

        #expect(try call("open", pathAddress, dirty | 0x200) == 5)
        #expect(try call("write", dirty | 5, payloadAddress, 6) == 6)
        #expect(try call("fstat", dirty | 5, statBuffer) == 0)
        #expect(try machine.engine.read(statBuffer + 4, as: UInt16.self) == 0x8180)
        #expect(try machine.engine.read(statBuffer + 96, as: UInt64.self) == 6)

        // Reopen without O_TRUNC and read with dirty upper bits on fd.
        #expect(try call("open", pathAddress, dirty) == 5)
        #expect(try call("read", dirty | 5, readBuffer, 6) == 6)
        #expect(try machine.engine.read(readBuffer, 6) == Data("hello!".utf8))

        // Reopen with O_TRUNC clears existing adi.pb.
        #expect(try call("open", pathAddress, dirty | 0x400) == 5)
        #expect(services.files[ADIRuntime.statePath]?.isEmpty == true)

        // procPIDPath truncates uint32_t buffersize.
        #expect(try call("procPIDPath", 0, readBuffer, dirty | 8) == .max)

        // Time clamping and null-pointer guards.
        services.now = { Date(timeIntervalSince1970: -100.5) }
        #expect(try call("currentTime", 0) == 0)
        #expect(try call("clockGetCalendarMicrotime", 0, 0) == 0)
        let tvAddress = try machine.scratch(size: 16)
        #expect(try call("gettimeofday", tvAddress, 0) == 0)
        #expect(try machine.engine.read(tvAddress, as: UInt64.self) == 0)
        #expect(try machine.engine.read(tvAddress + 8, as: UInt32.self) == 0)

        let nearSecond = Date(timeIntervalSince1970: Double(1_700_000_000).nextDown)
        services.now = { nearSecond }
        let secAddress = try machine.scratch(size: 4)
        let usecAddress = try machine.scratch(size: 4)
        #expect(try call("clockGetCalendarMicrotime", secAddress, usecAddress) == 0)
        #expect(try machine.engine.read(secAddress, as: UInt32.self) == 1_699_999_999)
        #expect(try machine.engine.read(usecAddress, as: UInt32.self) == 999_999)

        // readRandom fills non-8-byte-aligned lengths cleanly.
        let randomAddress = try machine.scratch(size: 37)
        #expect(try call("readRandom", randomAddress, 37) == 0)
        let randomBytes = try machine.engine.read(randomAddress, 37)
        #expect(randomBytes != Data(count: 37))
    }

    @Test(.enabled(if: hasAnyBackend), arguments: availableBackends)
    func xpcRefcountingFreesGuestHeapAllocations(backend: AnisetteConfiguration.Backend) async throws {
        let machine = try await Self.syntheticMachine(backend: backend)
        let services = machine.services

        func call(_ handler: String, _ arguments: UInt64...) throws -> UInt64 {
            try machine.call(handler, arguments)
        }

        let payload = Data("xpc-payload-bytes".utf8)
        let object = services.newXPCObject(payload)
        let lengthAddress = try machine.scratch(size: 8)
        let pointer = try call("xpcDictionaryGetData", object, 0, lengthAddress)
        #expect(pointer != 0)
        #expect(try machine.engine.read(lengthAddress, as: UInt64.self) == UInt64(payload.count))
        #expect(services.allocations.count == 1)
        #expect(services.xpcObjects.count == 1)

        // Retaining bumps refcount; first release keeps the object and its heap buffer alive.
        #expect(try call("xpcRetain", object) == object)
        #expect(services.xpcObjects[object]?.retainCount == 2)
        #expect(try call("xpcRelease", object) == 0)
        #expect(services.xpcObjects[object]?.retainCount == 1)
        #expect(services.allocations.count == 1)

        // Final release removes the XPC object and frees its guest heap allocation.
        #expect(try call("xpcRelease", object) == 0)
        #expect(services.xpcObjects.isEmpty)
        #expect(services.allocations.isEmpty)
        #expect(services.heapCursor == 0)

        // Releasing an unknown handle is a safe no-op.
        #expect(try call("xpcRelease", object) == 0)
    }

    @Test(.enabled(if: environment["ANISETTE_APPLE_DIR"] != nil))
    func repeatedUnprovisionedOTPRequestsDoNotLeakXPCOrHeap() async throws {
        let context = try await AnisetteContext.open(identifier: UUID(), configuration: AnisetteTests.cachedRuntime)
        for _ in 0..<20 {
            let error = await #expect(throws: AnisetteError.self) { try await context.requestOTP() }
            #expect(error?.adiStatus == AnisetteError.notProvisionedStatus)
        }
        await context.close()
    }
}
#endif
