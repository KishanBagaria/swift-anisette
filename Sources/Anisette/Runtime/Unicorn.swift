import Foundation
import CAnisette

/// Engines and their library are confined to Anisette's serial worker queue.
final class UnicornLibrary {
    let pointer: OpaquePointer
    init(url: URL) throws {
        guard let pointer = anisette_library_open(url.path) else {
            throw AnisetteError("Cannot load Unicorn: \(String(cString: anisette_library_error()))")
        }
        self.pointer = pointer
    }
    deinit { anisette_library_close(pointer) }
}

final class Unicorn: GuestEngine {
    // ARM64 register IDs from Unicorn 2.1's arm64.h.
    static let fp: Int32 = 1
    static let lr: Int32 = 2
    static let sp: Int32 = 4
    static let x0: Int32 = 199
    static let v0: Int32 = 228
    static let pc: Int32 = 260
    let pointer: OpaquePointer
    private let library: UnicornLibrary
    let cancellation: Cancellation
    private var serviceHandler: ((UInt64) -> Void)?
    var emulatesUnsupportedInstructions: Bool { true }

    init(library: UnicornLibrary, cancellation: Cancellation) throws {
        self.library = library
        self.cancellation = cancellation
        var engine: OpaquePointer?
        let code = anisette_engine_open(library.pointer, cancellation.pointer, &engine)
        guard code == 0, let engine else { throw AnisetteError("Cannot initialize Unicorn: \(code)") }
        pointer = engine
    }

    deinit { anisette_engine_close(pointer) }

    private static func registerID(for reg: GuestRegister) throws -> Int32 {
        switch reg {
        case .x(let index):
            try require((0...30).contains(index), "Invalid guest register x\(index)")
            switch index {
            case 29: return Self.fp
            case 30: return Self.lr
            default: return Self.x0 + Int32(index)
            }
        case .sp: return Self.sp
        case .pc: return Self.pc
        }
    }

    func check(_ code: Int32) throws {
        if code != 0 { throw AnisetteError("Unicorn: \(String(cString: anisette_engine_error(pointer, code)))") }
    }

    func map(_ address: UInt64, _ size: UInt64) throws {
        try require(size > 0 && size <= 1 << 30, "Invalid guest mapping size")
        try check(anisette_engine_map(pointer, address, Int(size)))
    }

    func read(_ address: UInt64, _ size: UInt64) throws -> Data {
        try require(size <= 64 << 20, "Guest transfer exceeds 64 MiB")
        if size == 0 { return Data() }
        _ = try guestAddress(address, offset: size - 1)
        var data = Data(count: Int(size))
        try data.withUnsafeMutableBytes { try check(anisette_engine_read(pointer, address, $0.baseAddress, $0.count)) }
        return data
    }

    func write(_ address: UInt64, _ data: Data) throws {
        if data.isEmpty { return }
        try require(data.count <= 64 << 20, "Guest transfer exceeds 64 MiB")
        _ = try guestAddress(address, offset: UInt64(data.count - 1))
        try data.withUnsafeBytes { try check(anisette_engine_write(pointer, address, $0.baseAddress, $0.count)) }
    }

    func register(_ reg: GuestRegister) throws -> UInt64 {
        var value: UInt64 = 0
        try check(anisette_engine_register_read(pointer, try Self.registerID(for: reg), &value))
        return value
    }

    func register(_ reg: GuestRegister, _ value: UInt64) throws {
        var value = value
        try check(anisette_engine_register_write(pointer, try Self.registerID(for: reg), &value))
    }

    func vector(_ index: Int) throws -> Data {
        try require((0...31).contains(index), "Invalid guest vector register v\(index)")
        var data = Data(count: 16)
        try data.withUnsafeMutableBytes { try check(anisette_engine_register_read(pointer, Self.v0 + Int32(index), $0.baseAddress)) }
        return data
    }

    func vector(_ index: Int, _ data: Data) throws {
        try require((0...31).contains(index), "Invalid guest vector register v\(index)")
        try require(data.count == 16, "Invalid vector register width")
        try data.withUnsafeBytes { try check(anisette_engine_register_write(pointer, Self.v0 + Int32(index), $0.baseAddress)) }
    }

    func writeReturnTrap(at address: UInt64) throws {
        try write(address, UInt32(0xd4200000)) // BRK #0
    }

    func installServiceStub(at address: UInt64) throws {
        try write(address, UInt32(0xd65f03c0)) // RET
    }

    func installServiceDispatcher(range: Range<UInt64>, handler: @escaping (UInt64) -> Void) throws {
        try require(!range.isEmpty, "Invalid guest service range")
        serviceHandler = handler
        let context = Unmanaged.passUnretained(self).toOpaque()
        try check(anisette_engine_hook(pointer, range.lowerBound, range.upperBound - 1, { context, address, _ in
            guard let context else { return }
            let engine = Unmanaged<Unicorn>.fromOpaque(context).takeUnretainedValue()
            engine.serviceHandler?(address)
        }, context))
    }

    func start(_ begin: UInt64, until end: UInt64, timeout: UInt64) throws {
        try cancellation.check()
        let code = anisette_engine_start(pointer, begin, end, timeout)
        try cancellation.check()
        try check(code)
    }

    func stop() { _ = anisette_engine_stop(pointer) }
}
