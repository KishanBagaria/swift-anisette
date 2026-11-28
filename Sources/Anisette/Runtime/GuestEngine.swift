import Foundation
import CAnisette

final class Cancellation: @unchecked Sendable {
    let pointer: OpaquePointer
    private let lock = NSLock()
    private var handlers: [UUID: @Sendable () -> Void] = [:]

    init() throws {
        guard let pointer = anisette_cancellation_create() else { throw AnisetteError("Cannot allocate cancellation flag") }
        self.pointer = pointer
    }

    deinit { anisette_cancellation_destroy(pointer) }

    func cancel() {
        anisette_cancellation_cancel(pointer)
        lock.lock()
        let active = Array(handlers.values)
        handlers.removeAll()
        lock.unlock()
        for handler in active { handler() }
    }

    var isCancelled: Bool { anisette_cancellation_is_cancelled(pointer) }

    func check() throws {
        if isCancelled { throw CancellationError() }
    }

    func addHandler(_ handler: @escaping @Sendable () -> Void) -> UUID? {
        lock.lock()
        defer { lock.unlock() }
        if anisette_cancellation_is_cancelled(pointer) { return nil }
        let id = UUID()
        handlers[id] = handler
        return id
    }

    func removeHandler(_ id: UUID) {
        lock.lock()
        handlers.removeValue(forKey: id)
        lock.unlock()
    }
}

enum GuestRegister: Hashable, Sendable {
    case x(Int)
    case sp
    case pc

    static let lr: Self = .x(30)
    static let x0: Self = .x(0)
}

protocol GuestEngine: AnyObject {
    var cancellation: Cancellation { get }
    var emulatesUnsupportedInstructions: Bool { get }
    func map(_ address: UInt64, _ size: UInt64) throws
    func read(_ address: UInt64, _ size: UInt64) throws -> Data
    func write(_ address: UInt64, _ data: Data) throws
    func register(_ reg: GuestRegister) throws -> UInt64
    func register(_ reg: GuestRegister, _ value: UInt64) throws
    func vector(_ index: Int) throws -> Data
    func vector(_ index: Int, _ data: Data) throws
    func writeReturnTrap(at address: UInt64) throws
    func installServiceStub(at address: UInt64) throws
    func installServiceDispatcher(range: Range<UInt64>, handler: @escaping (UInt64) -> Void) throws
    func start(_ begin: UInt64, until end: UInt64, timeout: UInt64) throws
    func stop()
}

extension GuestEngine {
    func read<T: FixedWidthInteger>(_ address: UInt64, as type: T.Type) throws -> T {
        try read(address, UInt64(MemoryLayout<T>.size)).integer(at: 0)
    }

    func write<T: FixedWidthInteger>(_ address: UInt64, _ value: T) throws {
        try write(address, .littleEndian(value))
    }
}
