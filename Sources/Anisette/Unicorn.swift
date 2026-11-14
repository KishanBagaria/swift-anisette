import Foundation
import CAnisette

final class Cancellation: @unchecked Sendable {
    let pointer: OpaquePointer
    init() throws {
        guard let pointer = anisette_cancellation_create() else { throw AnisetteError("Cannot allocate cancellation flag") }
        self.pointer = pointer
    }
    deinit { anisette_cancellation_destroy(pointer) }
    func cancel() { anisette_cancellation_cancel(pointer) }
    func check() throws {
        if anisette_cancellation_is_cancelled(pointer) { throw CancellationError() }
    }
}

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

final class Unicorn {
    static let x0: Int32 = 199
    static let lr: Int32 = 2
    static let sp: Int32 = 4
    static let pc: Int32 = 260
    let pointer: OpaquePointer
    private let library: UnicornLibrary
    let cancellation: Cancellation

    init(library: UnicornLibrary, cancellation: Cancellation) throws {
        self.library = library
        self.cancellation = cancellation
        var engine: OpaquePointer?
        let code = anisette_engine_open(library.pointer, cancellation.pointer, &engine)
        guard code == 0, let engine else { throw AnisetteError("Cannot initialize Unicorn: \(code)") }
        pointer = engine
    }

    deinit { anisette_engine_close(pointer) }

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
    func read<T: FixedWidthInteger>(_ address: UInt64, as type: T.Type) throws -> T {
        try read(address, UInt64(MemoryLayout<T>.size)).integer(at: 0)
    }
    func write<T: FixedWidthInteger>(_ address: UInt64, _ value: T) throws {
        try write(address, .littleEndian(value))
    }
    func register(_ index: Int32) throws -> UInt64 {
        var value: UInt64 = 0
        try check(anisette_engine_register_read(pointer, index, &value))
        return value
    }
    func register(_ index: Int32, _ value: UInt64) throws {
        var value = value
        try check(anisette_engine_register_write(pointer, index, &value))
    }
    func vector(_ index: Int32) throws -> Data {
        var data = Data(count: 16)
        try data.withUnsafeMutableBytes { try check(anisette_engine_register_read(pointer, index, $0.baseAddress)) }
        return data
    }
    func vector(_ index: Int32, _ data: Data) throws {
        try require(data.count == 16, "Invalid vector register width")
        try data.withUnsafeBytes { try check(anisette_engine_register_write(pointer, index, $0.baseAddress)) }
    }
    func start(_ begin: UInt64, until end: UInt64, timeout: UInt64) throws {
        try cancellation.check()
        let code = anisette_engine_start(pointer, begin, end, timeout)
        try cancellation.check()
        try check(code)
    }
    func stop() { _ = anisette_engine_stop(pointer) }
}
