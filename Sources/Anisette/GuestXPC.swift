import Foundation

extension GuestServices {
    // swiftlint:disable cyclomatic_complexity
    func xpcService(_ name: String) throws -> Bool {
        switch name {
        case "xpcConnectionSendMessageWithReplySync": try result(newXPCObject(xpcSyncReply))
        case "xpcConnectionCreateMachService", "xpcDictionaryCreateEmpty", "xpcDictionaryCreateReply":
            try result(newXPCObject(nil))
        case "xpcConnectionSetEventHandler":
            let data = try engine.read(argument(1), 64)
            let address = try allocate(64)
            try engine.write(address, data); xpcEventHandler = address; try result(0)
        case "xpcDictionaryGetAuditToken":
            let address = try argument(1)
            if address != 0 {
                var data = Data(count: 32)
                try data.put(UInt32.max, at: 0)
                try data.put(UInt32(123), at: 20)
                try data.put(UInt32(100000), at: 24)
                try data.put(UInt32(1), at: 28)
                try engine.write(address, data)
            }
            try result(0)
        case "xpcDictionarySendReply":
            if let data = xpcObjects[try argument(0)]?.data { xpcReply = data }
            xpcReplied = true; try result(0)
        case "xpcGetType":
            let object = try argument(0)
            try result(xpcObjects[object] != nil ? symbols["__xpc_type_dictionary"] ?? 0 : 0)
        case "xpcDictionarySetData":
            let object = try argument(0), count = try argument(3)
            try require(count <= 1 << 20, "XPC data exceeds limit")
            xpcData = try engine.read(argument(2), count)
            xpcObjects[object]?.data = xpcData
            try result(0)
        case "xpcDictionaryGetData":
            let object = try argument(0), lengthAddress = try argument(2)
            guard var value = xpcObjects[object], let data = value.data else {
                if lengthAddress != 0 { try engine.write(lengthAddress, UInt64(0)) }
                try result(0); return true
            }
            if value.address == 0 {
                value.address = try allocate(UInt64(max(data.count, 1)))
                try engine.write(value.address, data)
                xpcObjects[object] = value
            }
            if lengthAddress != 0 { try engine.write(lengthAddress, UInt64(data.count)) }
            try result(value.address)
        case "machMsgRPCFromKernel":
            let address = try argument(0), count = try argument(1), capacity = try argument(2)
            try require(count > 0 && count <= 1 << 20 && capacity <= 1 << 20, "Invalid Mach RPC size")
            guard let machRPCHandler else { throw AnisetteError("Missing Mach RPC handler") }
            let reply = try machRPCHandler(engine.read(address, count), Int(capacity))
            try require(!reply.isEmpty && reply.count <= capacity, "Invalid Mach RPC reply")
            try engine.write(address, reply); try result(0)
        case "machMsg":
            let address = try argument(0), size = try argument(2)
            try require(size > 0 && size <= 1 << 20, "Invalid Mach message size")
            machMessageReply = try engine.read(address, size)
            try result(0)
        default: return false
        }
        return true
    }
    // swiftlint:enable cyclomatic_complexity
}
