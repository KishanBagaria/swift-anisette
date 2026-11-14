import Foundation
import CAnisette

/// The guest sees a small virtual Darwin environment. Files and pointers here
/// belong to the emulator, and are never forwarded to host APIs.
final class GuestServices {
    static let base: UInt64 = 0x7ff880000000
    static let fakeHandle = UInt64.max
    let engine: Unicorn
    let profile: Profile
    let icxs: Data
    let pauseRunLoop: Bool
    var pausedAtRunLoop = false
    var fault: Error?
    var symbols: [String: UInt64]
    /// Guest stub address to the name of the handler `dispatch` runs for it.
    var entries: [UInt64: String] = [:]
    var codeCursor = base + 0x70000
    var dataCursor = base + 0x80000
    var errnoAddress: UInt64 = 0
    var heapCursor: UInt64 = 0
    struct Allocation { var size: UInt64; let reserved: UInt64 }
    var allocations: [UInt64: Allocation] = [:]
    var freeBlocks: [Range<UInt64>] = []
    var iterator: UInt64 = 0
    var callbackReturns: [UInt64] = []
    var hostUUID = Data(count: 16)
    var files: [String: Data] = [:]
    var filePath = ""
    var fileOffset = 0
    var icxsOffset = 0
    struct XPCObject { var data: Data?; var address: UInt64 = 0 }
    var xpcObjects: [UInt64: XPCObject] = [:]
    var nextXPC: UInt64 = 0xffff000000000000
    var xpcData = Data()
    var xpcReply = Data()
    var xpcReplied = false
    var xpcSyncReply: Data?
    var xpcEventHandler: UInt64 = 0
    var machPortCallback: UInt64 = 0
    var machPortInfo: UInt64 = 0
    var machMessageReply = Data()
    /// Runs the kernel FairPlay call on an indirect buffer, returning the updated buffer and status.
    var fairPlayHandler: ((Data) throws -> (Data, Int32))?
    var machRPCHandler: ((Data, Int) throws -> Data)?
    var aesService: UInt64 = 0
    var bufferVtable: UInt64 = 0

    init(engine: Unicorn, profile: Profile, pauseRunLoop: Bool) throws {
        self.engine = engine
        self.profile = profile
        self.icxs = profile.icxs
        self.pauseRunLoop = pauseRunLoop
        self.symbols = profile.imports
        try engine.map(Self.base, 1 << 20)
        for (symbol, address) in symbols {
            entries[address] = Self.handlers[symbol] ?? symbol
            try engine.write(address, UInt32(0xd65f03c0))
        }
        errnoAddress = try addData("guest.errno", Data(count: 8))
        try addData("___stack_chk_guard", Data([0xa5, 0x71, 0x3c, 0xd9, 0x86, 0x42, 0xef, 0x10]))
        for symbol in ["_NDR_record", "_kCFAllocatorDefault", "_kCFAllocatorNull",
                       "_kDADiskDescriptionVolumeUUIDKey", "_kIOMasterPortDefault"] {
            try addData(symbol, Data(count: 8))
        }
        for (symbol, value) in ["_kCFBooleanFalse": Self.fakeHandle, "_kCFBooleanTrue": Self.fakeHandle,
                                "__xpc_type_dictionary": 0xffff100000000001,
                                "__xpc_type_error": 0xffff100000000002,
                                "__xpc_error_connection_invalid": 0xffff100000000003] {
            try addData(symbol, .littleEndian(value))
        }
        try addFunction("callback.complete", handler: "callbackComplete")
        let context = Unmanaged.passUnretained(self).toOpaque()
        let end = GuestServices.base + 0x7ffff
        try engine.check(anisette_engine_hook(engine.pointer, GuestServices.base, end, { context, address, _ in
            guard let context else { return }
            let services = Unmanaged<GuestServices>.fromOpaque(context).takeUnretainedValue()
            do {
                guard let handler = services.entries[address] else { throw AnisetteError("Unknown guest service") }
                try services.dispatch(handler)
            } catch {
                if services.fault == nil { services.fault = error }
                services.engine.stop()
            }
        }, context))
    }

    @discardableResult
    func addData(_ name: String, _ data: Data) throws -> UInt64 {
        let address: UInt64
        if let existing = symbols[name] { address = existing } else {
            dataCursor = try guestAligned(dataCursor, to: 8)
            try require(UInt64(data.count) <= Self.base + (1 << 20) - dataCursor, "Guest service data area exhausted")
            address = dataCursor
            dataCursor += UInt64(max(data.count, 8))
            symbols[name] = address
        }
        try engine.write(address, data)
        return address
    }

    @discardableResult
    func addFunction(_ name: String, handler: String) throws -> UInt64 {
        if let address = symbols[name] { return address }
        try require(codeCursor + 16 <= Self.base + 0x80000, "Guest service code area exhausted")
        let address = codeCursor
        codeCursor += 16
        try engine.write(address, UInt32(0xd65f03c0))
        symbols[name] = address
        entries[address] = handler
        return address
    }

    func argument(_ index: Int) throws -> UInt64 {
        if index < 8 { return try engine.register(Unicorn.x0 + Int32(index)) }
        return try engine.read(guestAddress(engine.register(Unicorn.sp), offset: UInt64((index - 8) * 8)), as: UInt64.self)
    }

    func result(_ value: UInt64) throws { try engine.register(Unicorn.x0, value) }

    func string(_ address: UInt64, maximum: UInt64 = 4096) throws -> String {
        var data = Data()
        var offset: UInt64 = 0
        while offset < maximum {
            let current = try guestAddress(address, offset: offset)
            let chunk = try engine.read(current, min(maximum - offset, 4096 - current % 4096))
            if let end = chunk.firstIndex(of: 0) {
                data.append(chunk.prefix(upTo: end))
                return String(decoding: data, as: UTF8.self)
            }
            data.append(chunk)
            offset += UInt64(chunk.count)
        }
        throw AnisetteError("Unterminated guest string")
    }

    func newXPCObject(_ data: Data?) -> UInt64 {
        nextXPC += 1
        xpcObjects[nextXPC] = XPCObject(data: data)
        return nextXPC
    }
}
