import Foundation

/// Apple code executes only inside four isolated Unicorn machines. This object
/// and every guest callback are confined to the library's serial worker queue.
final class ADIRuntime {
    static let statePath = "/var/db/fpsd/adi/adi.pb"
    let client: GuestMachine
    let daemon: GuestMachine
    let fairplay: GuestMachine
    let kernel: GuestMachine
    private let entries: Profile.Entries
    private var kernelContext: UInt64 = 0
    private var daemonHandler: UInt64 = 0

    init(identifier: Data, state: Data, profile: Profile, library: UnicornLibrary, cancellation: Cancellation) throws {
        try require(identifier.count == 16, "ADI identifier must contain 16 bytes")
        entries = profile.entries
        func machine(_ name: String, pauseRunLoop: Bool = false) throws -> GuestMachine {
            try GuestMachine(name: name, profile: profile, library: library, cancellation: cancellation,
                             pauseRunLoop: pauseRunLoop)
        }
        client = try machine("commerce")
        daemon = try machine("adid", pauseRunLoop: true)
        fairplay = try machine("fairplayd", pauseRunLoop: true)
        kernel = try machine("FairPlayIOKit")
        for machine in [client, daemon, fairplay, kernel] { machine.services.hostUUID = identifier }
        if !state.isEmpty { daemon.services.files[Self.statePath] = state }
        kernel.services.machRPCHandler = { [weak self] data, size in
            guard let self else { throw AnisetteError("ADI session is closed") }
            return try self.machRPC(data, capacity: size)
        }
        try initializeKernel()
        let handler: (Data) throws -> (Data, Int32) = { [weak self] indirect in
            guard let self else { throw AnisetteError("ADI session is closed") }
            return try self.fairPlay(indirect)
        }
        fairplay.services.fairPlayHandler = handler
        try fairplay.invoke(entries.fairPlayDaemonMain, 0, 0, 0)
        daemon.services.fairPlayHandler = handler
        client.services.fairPlayHandler = handler
        _ = try? daemon.invoke(entries.daemonMain, 0, 0, 0, 0)
        let listener = daemon.services.xpcEventHandler
        try require(listener != 0, "ADI daemon did not install a listener")
        try invokeDaemonBlock(listener, argument: daemon.services.newXPCObject(nil))
        daemonHandler = daemon.services.xpcEventHandler
        try require(daemonHandler != listener && daemonHandler != 0, "ADI daemon did not install a request handler")
    }

    private func initializeKernel() throws {
        defer { kernel.clearScratch() }
        try kernel.invoke(entries.kernelStart)
        try checkStatus(kernel.invoke(entries.kernelSetup))
        let output = try kernel.scratch(size: 8)
        let task = try kernel.services.allocate(4096)
        try kernel.engine.write(task, Data(count: 4096))
        try checkStatus(kernel.invoke(entries.kernelInit, 0, output, 0, task))
        kernelContext = try kernel.engine.read(output, as: UInt64.self)
        try require(kernelContext != 0, "FairPlay kernel returned no session context")
    }

    private func checkStatus(_ status: UInt64) throws {
        let code = Int32(truncatingIfNeeded: status)
        guard code == 0 else { throw AnisetteError("Apple ADI returned error \(code)", adiStatus: code) }
    }

    private func fairPlay(_ indirect: Data) throws -> (Data, Int32) {
        let probe = try kernel.engine.read(entries.kernelStackProbe, as: UInt64.self)
        try require(probe == entries.kernelStackProbeValue, "Unexpected FairPlay kernel stack probe")
        defer { kernel.clearScratch() }
        let address = try kernel.scratch(indirect)
        let status = try kernel.invoke(entries.kernelMessage, address, UInt64(indirect.count), kernelContext)
        let updated = try kernel.engine.read(address, UInt64(indirect.count))
        return (updated, Int32(truncatingIfNeeded: status))
    }

    private func machRPC(_ request: Data, capacity: Int) throws -> Data {
        try require(fairplay.services.machPortCallback != 0, "FairPlay daemon has no Mach callback")
        defer { fairplay.clearScratch() }
        let address = try fairplay.scratch(request, size: UInt64(max(request.count, capacity)))
        fairplay.services.machMessageReply = Data()
        try fairplay.invoke(fairplay.services.machPortCallback, .max, address, UInt64(request.count), fairplay.services.machPortInfo)
        try require(!fairplay.services.machMessageReply.isEmpty, "FairPlay daemon returned no Mach reply")
        return fairplay.services.machMessageReply
    }

    private func invokeDaemonBlock(_ block: UInt64, argument: UInt64) throws {
        let handler = try daemon.engine.read(guestAddress(block, offset: 16), as: UInt64.self)
        try daemon.invoke(handler, block, argument)
    }

    private func invoke(_ address: UInt64, _ arguments: UInt64...) throws -> UInt64 {
        client.services.xpcData = Data()
        client.services.xpcSyncReply = nil
        let firstResult = Result { try client.invoke(address, arguments: arguments) }
        try client.engine.cancellation.check()
        let request = client.services.xpcData
        if request.isEmpty {
            // A reused client can satisfy an OTP call locally. The caller still
            // validates Apple's status and output buffers before accepting it.
            return try firstResult.get()
        }
        daemon.services.xpcReply = Data()
        daemon.services.xpcReplied = false
        try invokeDaemonBlock(daemonHandler, argument: daemon.services.newXPCObject(request))
        try require(daemon.services.xpcReplied && !daemon.services.xpcReply.isEmpty, "ADI daemon returned no reply")
        client.services.xpcSyncReply = daemon.services.xpcReply
        return try client.invoke(address, arguments: arguments)
    }

    func startProvisioning(_ challenge: Data) throws -> (UInt32, Data) {
        try require(!challenge.isEmpty && challenge.count <= 1 << 20, "Invalid provisioning challenge")
        defer { client.clearScratch() }
        let input = try client.scratch(challenge)
        let pointer = try client.scratch(size: 8), length = try client.scratch(size: 4), session = try client.scratch(size: 4)
        try checkStatus(invoke(entries.startProvisioning, UInt64.max - 1, input, UInt64(challenge.count), pointer, length, session))
        return (try client.engine.read(session, as: UInt32.self), try readOutput(pointer: pointer, length: length))
    }

    func endProvisioning(session: UInt32, ptm: Data, tk: Data) throws -> Data {
        try require(!ptm.isEmpty && ptm.count <= 1 << 20 && !tk.isEmpty && tk.count <= 1 << 20, "Invalid provisioning completion")
        defer { client.clearScratch() }
        let metadata = try client.scratch(ptm), key = try client.scratch(tk)
        try checkStatus(invoke(entries.endProvisioning, UInt64(session), metadata, UInt64(ptm.count), key, UInt64(tk.count)))
        return try state()
    }

    func requestOTP() throws -> (Data, Data, Data) {
        defer { client.clearScratch() }
        let mid = try client.scratch(size: 8), midLength = try client.scratch(size: 4)
        let otp = try client.scratch(size: 8), otpLength = try client.scratch(size: 4)
        try checkStatus(invoke(entries.requestOTP, UInt64.max - 1, mid, midLength, otp, otpLength))
        return (try readOutput(pointer: mid, length: midLength), try readOutput(pointer: otp, length: otpLength), try state())
    }

    private func readOutput(pointer: UInt64, length: UInt64) throws -> Data {
        let address = try client.engine.read(pointer, as: UInt64.self)
        let count = try client.engine.read(length, as: UInt32.self)
        try require(count > 0 && count <= 16 << 20 && address != 0, "Invalid ADI output buffer")
        return try client.engine.read(address, UInt64(count))
    }

    private func state() throws -> Data {
        guard let data = daemon.services.files[Self.statePath], !data.isEmpty else { throw AnisetteError("ADI state was not created") }
        return data
    }
}
