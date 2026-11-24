import Foundation

private enum Sysconf {
    static let pageSize: Int32 = 29
    static let nprocessorsConf: Int32 = 57
    static let nprocessorsOnln: Int32 = 58
    static let physPages: Int32 = 200
}

extension GuestServices {
    // The cases implement Darwin's guest ABI, rather than calling host Darwin APIs.
    // swiftlint:disable cyclomatic_complexity function_body_length
    func dispatch(_ name: String) throws {
        if try memoryService(name) || kernelService(name) || fileService(name) || xpcService(name) { return }
        switch name {
        case "returnZero", "_pthread_mutex_init", "_pthread_mutex_destroy", "_pthread_rwlock_rdlock$UNIX2003":
            try result(0)
        case "returnOne": try result(1)
        case "returnTwo": try result(2)
        case "returnThree": try result(3)
        case "returnFakeHandle", "returnMinusOne": try result(.max)
        case "returnUnchanged": break
        case "abort": throw AnisetteError("Guest aborted")
        case "errorPointer": try result(errnoAddress)
        case "kqueue": try result(6)
        case "cfRunLoopRun":
            if pauseRunLoop { pausedAtRunLoop = true; engine.stop() } else { try result(0) }
        case "cfMachPortCreateWithPort":
            machPortCallback = try argument(2)
            let context = try argument(3)
            if context != 0 { machPortInfo = try engine.read(guestAddress(context, offset: 8), as: UInt64.self) }
            let flag = try argument(4)
            if flag != 0 { try engine.write(flag, UInt8(0)) }
            try result(.max)
        case "cfStringCreate":
            let value = try string(argument(1))
            try result(["IOPlatformSerialNumber", "IOPlatformUUID", "board-id"].contains(value) ? .max : 0)
        case "cfStringCreateNoCopy": try result(argument(1))
        case "cfNumberGetValue":
            let address = try argument(2)
            if address != 0 { try engine.write(address, UInt32(3184554750)) }
            try result(1)
        case "cfStringGetCString":
            let address = try argument(0), buffer = try argument(1), capacity = try argument(2)
            guard buffer != 0 && capacity > 0 else { try result(0); return }
            let text = address != 0 && address != .max ? (try? string(address)) ?? "" : ""
            let data = Data(text.utf8) + Data([0])
            guard data.count <= capacity else { try result(0); return }
            try engine.write(buffer, data); try result(1)
        case "ioIteratorNext": iterator += 1; try result(iterator % 2)
        case "ioMainPort", "ioServiceOpen", "ioRegistryEntryGetParentEntry", "ioServiceGetMatchingServices":
            let index = name == "ioMainPort" ? 1 : (name == "ioServiceOpen" ? 3 : 2)
            let address = try argument(index)
            if name == "ioServiceGetMatchingServices" { iterator = 0 }
            if address != 0 {
                let value: UInt32 = name == "ioMainPort" ? 0 : (name == "ioServiceOpen" ? 7 : .max)
                try engine.write(address, value)
            }
            try result(0)
        case "compareAndSwap32":
            let address = try argument(2)
            let current = try engine.read(address, as: UInt32.self)
            if current == (try argument32(0)) {
                try engine.write(address, try argument32(1)); try result(1)
            } else { try result(0) }
        case "arc4random": try result(UInt64(UInt32.random(in: .min ... .max)))
        case "random31": try result(UInt64(UInt32.random(in: 0...0x7fffffff)))
        case "arc4randomUniform":
            let upper = try argument32(0)
            try result(upper < 2 ? 0 : UInt64(UInt32.random(in: 0..<upper)))
        case "readRandom":
            let address = try argument(0), count = try argument(1)
            try require(count <= 64 << 20, "Guest random request exceeds limit")
            try engine.write(address, Self.randomBytes(count: Int(count)))
            try result(0)
        case "notifyRegisterCheck", "notifyCheck", "notifyGetState":
            let address = try argument(1)
            if address != 0 {
                if name == "notifyGetState" { try engine.write(address, UInt64(0)) } else {
                    try engine.write(address, UInt32(name == "notifyRegisterCheck" ? 1 : 0))
                }
            }
            try result(0)
        case "auditTokenToAU32":
            for (index, value) in [UInt32(0), 0, 0, 0, 0, 123, 100000, 1].enumerated() {
                let address = try argument(index + 1)
                if address != 0 { try engine.write(address, value) }
            }
            try result(0)
        case "bootstrapLookUp", "bootstrapCheckIn":
            let address = try argument(2)
            if address != 0 { try engine.write(address, UInt32(name == "bootstrapLookUp" ? 0 : 1)) }
            try result(name == "bootstrapLookUp" ? 5 : 0)
        case "dlopen":
            let path = try string(argument(0))
            try result(path == "/System/Library/PrivateFrameworks/CoreFP.framework/CoreFP" ? .max : 0)
        case "dlsym":
            let symbol = try string(argument(1))
            try result(profile.exports["_" + symbol] ?? 0)
        case "currentTime", "clockGetCalendarMicrotime", "gettimeofday": try timeService(name)
        case "gethostuuid":
            let address = try argument(0)
            if address != 0 { try engine.write(address, hostUUID) }
            try result(0)
        case "objcMsgSend": try result(string(argument(1)) == "objectForKey:" ? .max : 0)
        case "sysctlbyname": try sysctlService()
        case "sysconf":
            switch try signedArgument32(0) {
            case Sysconf.pageSize: try result(4096)
            case Sysconf.nprocessorsConf, Sysconf.nprocessorsOnln: try result(1)
            case Sysconf.physPages: try result(GuestMachine.heapSize / 4096)
            default: try result(.max)
            }
        case "pthreadOnce", "dispatchOnce": try once(name)
        case "callbackComplete":
            guard let address = callbackReturns.popLast() else { throw AnisetteError("Guest callback has no return address") }
            try engine.register(Unicorn.lr, address); try result(0)
        default: throw AnisetteError("Guest called unsupported import \(name)")
        }
    }
    // swiftlint:enable cyclomatic_complexity function_body_length

    private static func randomBytes(count: Int) -> Data {
        var generator = SystemRandomNumberGenerator()
        var data = Data(count: count)
        data.withUnsafeMutableBytes { buffer in
            guard let base = buffer.baseAddress else { return }
            var offset = 0
            while offset < buffer.count {
                var word = generator.next()
                let chunk = min(8, buffer.count - offset)
                withUnsafeBytes(of: &word) { bytes in
                    if let source = bytes.baseAddress {
                        base.advanced(by: offset).copyMemory(from: source, byteCount: chunk)
                    }
                }
                offset += chunk
            }
        }
        return data
    }

    private func timeService(_ name: String) throws {
        let time = max(0.0, now().timeIntervalSince1970)
        let seconds = UInt64(time)
        let microseconds = min(999_999, UInt32((time - floor(time)) * 1_000_000))
        let address = try argument(0)
        if name == "currentTime" {
            if address != 0 { try engine.write(address, seconds) }
            try result(seconds)
        } else if name == "clockGetCalendarMicrotime" {
            if address != 0 { try engine.write(address, UInt32(truncatingIfNeeded: seconds)) }
            let microsecondAddress = try argument(1)
            if microsecondAddress != 0 { try engine.write(microsecondAddress, microseconds) }
            try result(0)
        } else {
            if address != 0 {
                try engine.write(address, Data.littleEndian(seconds) + Data.littleEndian(microseconds) + Data(count: 4))
            }
            let zone = try argument(1)
            if zone != 0 { try engine.write(zone, UInt64(0)) }
            try result(0)
        }
    }

    private func sysctlService() throws {
        let name = try string(argument(0)), output = try argument(1), length = try argument(2)
        let value: Data
        switch name {
        case "kern.monotonicclock", "hw.ncpu", "hw.logicalcpu", "hw.physicalcpu", "hw.optional.arm64":
            value = .littleEndian(UInt32(1))
        case "hw.memsize": value = .littleEndian(UInt64(8 << 30))
        case "hw.machine": value = Data("arm64\0".utf8)
        default:
            guard let text = profile.system.sysctlValue(for: name) else { try result(.max); return }
            value = Data(text.utf8) + Data([0])
        }
        if length != 0 {
            if output != 0 {
                guard try engine.read(length, as: UInt64.self) >= value.count else { try result(.max); return }
                try engine.write(output, value)
            }
            try engine.write(length, UInt64(value.count))
        }
        try result(0)
    }

    private func once(_ name: String) throws {
        let predicate = try argument(0), block = try argument(1)
        let value = try engine.read(predicate, as: UInt64.self)
        let target: UInt64
        if name == "pthreadOnce" {
            guard value != 0 && value != 0x4f4e4345 else { try result(0); return }
            try engine.write(predicate, UInt64(0x4f4e4345))
            target = block
        } else {
            guard value != .max else { try result(0); return }
            try engine.write(predicate, UInt64.max)
            target = try engine.read(guestAddress(block, offset: 16), as: UInt64.self)
            try engine.register(Unicorn.x0, block)
        }
        callbackReturns.append(try engine.register(Unicorn.lr))
        guard let completion = symbols["callback.complete"] else { throw AnisetteError("Missing callback completion") }
        try engine.register(Unicorn.lr, completion)
        try engine.register(Unicorn.pc, target)
    }
}
