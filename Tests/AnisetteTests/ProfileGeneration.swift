#if os(macOS) || os(Linux)
import Foundation
import Testing
import MachOKit
@testable import Anisette

/// Derives the profile in `Sources/Anisette/Resources/Profile.json` from a build's binaries. Only the
/// names in `Pinned` are chosen by hand. `BuildRotation` drives it; see MAINTAINING.md.
enum ProfileGeneration {
    enum Pinned {
        /// commerce links ADI statically and strips its symbols, so its three ADI functions are found
        /// through the only methods that call them: `provision` calls start, a buffer free, then end;
        /// `strings` calls the OTP function, then the same buffer free.
        static let provisionSelector = "provisionDSID:withStoreClient:data:completionHandler:"
        static let stringsSelector = "adiStringsForDSID:returningMID:otp:error:"
        /// FairPlayIOKit keeps its symbol table, including local symbols, in the kernel collection.
        enum Kernel {
            static let start = "__Z14LSKDKext_startv"
            static let setup = "_cmam7f"
            static let initialize = "__ZN30com_apple_driver_FairPlayIOKit11Trped0719abEPPvjS0_"
            static let message = "_PRnut72j9"
            static let stackProbe = "___chkstk_darwin"
        }
        /// Imports in the function-pointer table that AppleMediaServices' obfuscated code keeps in
        /// __AUTH_CONST,__const. The table holds about 70 libSystem, xpc, CoreFoundation and IOKit
        /// functions; this subset was observed while running the upstream SAP signer and cannot be derived.
        static let functions = [
            "_malloc", "_free", "_dispatch_once", "_sysctlbyname", "_gettimeofday", "_arc4random", "___memset_chk",
            "_abort", "___error", "_pthread_once", "_pthread_rwlock_unlock", "_pthread_rwlock_wrlock",
            "_pthread_rwlock_init", "_strlen", "_CFStringCreateWithCString", "_CFStringGetLength",
            "_CFStringGetCString", "_CFRelease", "_CFDataGetLength", "_IOServiceMatching",
            "_IOServiceGetMatchingServices", "_IOIteratorNext", "_IOObjectRelease",
        ]
        /// Imports AppleMediaServices' code loads through shared-cache GOT slots outside the image.
        static let slots = ["___stack_chk_guard", "___chkstk_darwin"]
    }

    // MARK: Entries, from the extracted images alone

    static func entries(_ assets: [String: Data], kernelCollectionBase: UInt64) throws -> Profile.Entries {
        let commerce = try image("commerce", assets)
        let adi = try commerceEntries(commerce)
        func main(_ name: String) throws -> UInt64 {
            let image = try image(name, assets)
            return try guest(name, image, mainEntry(image))
        }
        let kernel = try image("FairPlayIOKit", assets)
        let symbols = try kernel.symbols()
        func symbol(_ name: String) throws -> UInt64 {
            // N_SECT: a definition in this image, not an import resolved from the kernel.
            let matches = symbols.filter { $0.name == name && $0.type & 0x0e == 0x0e }
            try require(matches.count == 1, "FairPlayIOKit must define \(name) once")
            return try guest("FairPlayIOKit", kernel, matches[0].value)
        }
        // A signed pointer constant to the kext's stack probe. ADIRuntime reads it before each kernel
        // call to detect a mis-relocated image. The section holds the pointer twice; either would do.
        let probe = try symbol(Pinned.Kernel.stackProbe)
        var slot: UInt64?
        for section in try sections(kernel) where section.segment == "__DATA_CONST" && section.name == "__auth_ptr" {
            for index in 0..<section.size / 8 {
                let raw: UInt64 = try kernel.data.integer(at: section.offset + index * 8)
                guard raw >> 30 & 3 == 0, raw & 0x3fffffff != 0 else { continue }
                let target = try guestAddress(kernelCollectionBase, offset: raw & 0x3fffffff)
                if kernel.contains(target), try guest("FairPlayIOKit", kernel, target) == probe {
                    slot = try guestAddress(section.address, offset: UInt64(index * 8))
                }
            }
        }
        return try Profile.Entries(
            startProvisioning: guest("commerce", commerce, adi.start), endProvisioning: guest("commerce", commerce, adi.end),
            requestOTP: guest("commerce", commerce, adi.otp), daemonMain: main("adid"), fairPlayDaemonMain: main("fairplayd"),
            kernelStart: symbol(Pinned.Kernel.start), kernelSetup: symbol(Pinned.Kernel.setup),
            kernelInit: symbol(Pinned.Kernel.initialize), kernelMessage: symbol(Pinned.Kernel.message),
            kernelStackProbe: guest("FairPlayIOKit", kernel, #require(slot)), kernelStackProbeValue: probe)
    }

    /// The addresses of commerce's ADI functions, from the call order described at `Pinned.provisionSelector`.
    /// Throws unless both methods have exactly that shape, so a restructured binary is never guessed at.
    static func commerceEntries(_ original: MachO) throws -> (start: UInt64, end: UInt64, otp: UInt64) {
        var image = original
        try image.relocate(to: image.base) { _ in 0 } // Turns chained fixups into plain addresses.
        let sections = try sections(image)
        func section(_ name: String) throws -> Section {
            let matches = sections.filter { $0.name == name }
            try require(matches.count == 1, "commerce must have one \(name) section")
            return matches[0]
        }
        let names = try section("__objc_methname"), references = try section("__objc_selrefs")
        let methods = try section("__objc_methlist"), text = try section("__text")
        let starts = try functionStarts(image)
        // Relative method lists, each 8-byte aligned: a header (entry size and flags, count), then entries of
        // three 32-bit offsets (name, types, implementation), each relative to its own field.
        var methodList: [(name: UInt64, implementation: UInt64)] = []
        var cursor = 0
        while cursor + 8 <= methods.size {
            let header: UInt32 = try image.data.integer(at: methods.offset + cursor)
            let count = Int(try image.data.integer(at: methods.offset + cursor + 4, as: UInt32.self))
            try require(header == 0x8000000c && count <= (methods.size - cursor - 8) / 12, "Unsupported commerce method list")
            for index in 0..<count {
                let offset = cursor + 8 + index * 12
                func target(_ field: Int) throws -> UInt64 {
                    let relative = Int64(try image.data.integer(at: methods.offset + offset + field, as: Int32.self))
                    return try addingSigned(methods.address + UInt64(offset + field), relative)
                }
                methodList.append((try target(0), try target(8)))
            }
            cursor = (cursor + 8 + count * 12 + 7) & ~7
        }
        let implementations = Set(methodList.map(\.implementation)).sorted()
        /// In-`__text` call targets of the method implementing `selector`, in order.
        func calls(_ selector: String) throws -> [UInt64] {
            let strings = try image.data.bytes(at: names.offset, size: names.size)
            let needle = Data(selector.utf8) + Data([0])
            var string: UInt64?
            var search = strings.startIndex
            while let found = strings.range(of: needle, in: search..<strings.endIndex) {
                if found.lowerBound == strings.startIndex || strings[found.lowerBound - 1] == 0 {
                    try require(string == nil, "commerce repeats the selector \(selector)")
                    string = names.address + UInt64(found.lowerBound - strings.startIndex)
                }
                search = found.upperBound
            }
            guard let string else { throw AnisetteError("commerce has no selector \(selector)") }
            var targets: Set<UInt64> = [string]
            for index in 0..<references.size / 8 where try image.data.integer(at: references.offset + index * 8) == string {
                targets.insert(references.address + UInt64(index * 8))
            }
            let matches = methodList.filter { targets.contains($0.name) }
            try require(matches.count == 1, "commerce must implement \(selector) once")
            // A method's blocks follow it, so its code runs to the next method's implementation.
            let start = matches[0].implementation
            guard starts.contains(start), let end = implementations.first(where: { $0 > start }) else {
                throw AnisetteError("\(selector) is not a function start")
            }
            var calls: [UInt64] = []
            for address in stride(from: start, to: end, by: 4) {
                let word: UInt32 = try image.data.integer(at: text.offset + Int(address - text.address))
                guard word & 0xfc000000 == 0x94000000 else { continue } // bl
                let target = try addingSigned(address, Int64(Int32(bitPattern: word << 6) >> 6) * 4)
                if target >= text.address && target - text.address < UInt64(text.size) { calls.append(target) }
            }
            return calls
        }
        let provision = try calls(Pinned.provisionSelector), strings = try calls(Pinned.stringsSelector)
        try require(strings.count >= 2 && provision.count >= 3, "commerce's ADI callers make too few calls")
        let free = strings[1]
        let entries = [provision[0], provision[2], strings[0]]
        try require(provision[1] == free && strings.dropFirst().allSatisfy { $0 == free }
            && Set(entries).count == 3 && !entries.contains(free)
            && entries.allSatisfy(starts.contains), "commerce's ADI callers no longer match the expected call order")
        return (provision[0], provision[2], strings[0])
    }

    static func image(_ name: String, _ assets: [String: Data]) throws -> MachO {
        guard let data = assets[name] else { throw AnisetteError("Missing Apple image \(name)") }
        return try MachO(data)
    }

    private static func guest(_ name: String, _ image: MachO, _ address: UInt64) throws -> UInt64 {
        try require(image.contains(address), "\(name) address lies outside the image")
        return try guestAddress(Profile.base(of: name, image: image), offset: address - image.base)
    }

    private static func mainEntry(_ image: MachO) throws -> UInt64 {
        guard let command = try image.command(UInt32(LC_MAIN), minimum: 24) else { throw AnisetteError("No LC_MAIN") }
        let offset: UInt64 = try image.data.integer(at: command + 8)
        let segment = image.segments.first { offset >= UInt64($0.offset) && offset - UInt64($0.offset) < UInt64($0.length) }
        guard let segment else { throw AnisetteError("LC_MAIN lies outside the image") }
        return try guestAddress(segment.address, offset: offset - UInt64(segment.offset))
    }

    private static func functionStarts(_ image: MachO) throws -> Set<UInt64> {
        guard let command = try image.command(UInt32(LC_FUNCTION_STARTS), minimum: 16) else { return [] }
        let offset = Int(try image.data.integer(at: command + 8, as: UInt32.self))
        let size = Int(try image.data.integer(at: command + 12, as: UInt32.self))
        let table = try image.data.bytes(at: offset, size: size)
        var starts: Set<UInt64> = [], address = image.base, cursor = 0
        while cursor < table.count {
            let delta = try table.uleb(&cursor)
            if delta == 0 { break }
            address = try guestAddress(address, offset: delta)
            starts.insert(address)
        }
        return starts
    }

    struct Section { let segment: String; let name: String; let address: UInt64; let offset: Int; let size: Int; let flags: UInt32 }

    static func sections(_ image: MachO) throws -> [Section] {
        func name(_ offset: Int) throws -> String {
            String(decoding: try image.data.bytes(at: offset, size: 16).prefix { $0 != 0 }, as: UTF8.self)
        }
        return try image.segments.flatMap { segment in
            let count = Int(try image.data.integer(at: segment.command + 64, as: UInt32.self))
            return try (0..<count).map { index in
                let item = segment.command + 72 + index * 80
                return Section(segment: try name(item + 16), name: try name(item), address: try image.data.integer(at: item + 32),
                               offset: Int(try image.data.integer(at: item + 48, as: UInt32.self)),
                               size: Int(try image.data.integer(at: item + 40, as: UInt64.self)),
                               flags: try image.data.integer(at: item + 64))
            }
        }
    }

    // MARK: Shared-cache functions and slots

    /// Binds each pinned import of AppleMediaServices in the cache. Functions must appear as data
    /// pointers in the image (what `MachO.prelink` replaces); each slot must be the one GOT slot outside
    /// the image that its code loads and that holds the import's address.
    static func sharedCacheTables(_ services: MachO, cache: SharedCacheSymbols) async throws
        -> (functions: [UInt64: String], slots: [UInt64: String]) {
        let (dependencies, _) = try SharedCacheSymbols.dependencies(services)
        var ordinals: [String: Int] = [:]
        for symbol in try services.symbols() where symbol.type & 0x0e == 0 && symbol.type & 1 != 0 {
            ordinals[symbol.name] = Int(symbol.description >> 8)
        }
        func resolve(_ name: String) async throws -> UInt64 {
            // Two-level namespace: the high byte of n_desc is the 1-based dependency index.
            guard let ordinal = ordinals[name], dependencies.indices.contains(ordinal - 1) else {
                throw AnisetteError("AppleMediaServices does not import \(name) from a named library")
            }
            let library = dependencies[ordinal - 1]
            guard let address = try await cache.address(of: name, in: library) else {
                throw AnisetteError("\(library) does not export \(name)")
            }
            return address
        }
        let pointers = try dataPointers(services)
        var functions: [UInt64: String] = [:]
        for name in Pinned.functions {
            let address = try await resolve(name)
            try require(pointers.contains(address), "AppleMediaServices holds no pointer to \(name)")
            try require(functions.updateValue(name, forKey: address) == nil, "Imports share address \(name)")
        }
        var contents: [UInt64: [UInt64]] = [:]
        for slot in try externalSlots(services).sorted() {
            if let value = try await cache.pointer(at: slot) { contents[value, default: []].append(slot) }
        }
        var slots: [UInt64: String] = [:]
        for name in Pinned.slots {
            let matches = try await contents[resolve(name)] ?? []
            try require(matches.count == 1, "Expected one shared-cache slot for \(name), found \(matches.count)")
            slots[matches[0]] = name
        }
        return (functions, slots)
    }

    /// Aligned 8-byte values in the writable segments, as `MachO.prelink` scans them.
    static func dataPointers(_ image: MachO) throws -> Set<UInt64> {
        var result: Set<UInt64> = []
        for segment in image.segments where segment.name != "__TEXT" && segment.name != "__LINKEDIT" && segment.length >= 8 {
            let start = segment.offset + Int((8 - segment.address % 8) % 8)
            for offset in stride(from: start, through: segment.offset + segment.length - 8, by: 8) {
                result.insert(try image.data.integer(at: offset))
            }
        }
        return result
    }

    /// Addresses outside the image that its code loads a pointer from: `adrp; ldr xN, [xA, #imm]`,
    /// or `adrp; add xB, xA, #imm; ldr xN, [xB]` as in arm64e authenticated calls through a GOT.
    static func externalSlots(_ image: MachO) throws -> Set<UInt64> {
        var result: Set<UInt64> = []
        for section in try sections(image) where section.flags & 0x80000400 != 0 && section.size >= 12 {
            let code = try image.data.bytes(at: section.offset, size: section.size & ~3)
            let words = code.withUnsafeBytes { bytes in
                (0..<bytes.count / 4).map { UInt32(littleEndian: bytes.loadUnaligned(fromByteOffset: $0 * 4, as: UInt32.self)) }
            }
            for index in 0..<words.count - 2 where words[index] & 0x9f000000 == 0x90000000 {
                let adrp = words[index], next = words[index + 1], register = adrp & 31
                let immediate = Int64(adrp >> 5 & 0x7ffff) << 2 | Int64(adrp >> 29 & 3)
                let pc = section.address + UInt64(index * 4)
                let page = UInt64(bitPattern: Int64(bitPattern: pc & ~4095) + ((immediate << 43) >> 31))
                var slot: UInt64?
                if next & 0xffc00000 == 0xf9400000 && next >> 5 & 31 == register {
                    slot = page &+ UInt64(next >> 10 & 0xfff) * 8
                } else if next & 0xffc00000 == 0x91000000 && next >> 5 & 31 == register,
                          words[index + 2] & 0xfffffc00 == 0xf9400000 && words[index + 2] >> 5 & 31 == next & 31 {
                    slot = page &+ UInt64(next >> 10 & 0xfff)
                }
                if let slot, !image.contains(slot) { result.insert(slot) }
            }
        }
        return result
    }

    // MARK: System versions, from the restore image

    /// Versions read from the restore image's system volume and kernel collection. The build number is not
    /// a reliable Darwin version, and Mach-O dependency versions truncate CFNetwork's full bundle version.
    static func systemInfo(_ tree: APFSTree, kernel: Data) async throws -> AnisetteSystemInfo {
        func read(_ path: String) async throws -> Data { try await AssetInstaller.framework(path, in: tree) }
        let system = try plist(await read("/System/Library/CoreServices/SystemVersion.plist"))
        let cfNetwork = try plist(await read("/System/Library/Frameworks/CFNetwork.framework/Versions/A/Resources/Info.plist"))
        let authKit = try plist(await read("/System/Library/PrivateFrameworks/AuthKit.framework/Versions/A/Resources/Info.plist"))
        let akd = try MachO(await read("/System/Library/PrivateFrameworks/AuthKit.framework/Versions/A/Support/akd"))
        guard let info = akd.sections.first(where: { $0.name == "__info_plist" }) else { throw AnisetteError("akd has no Info.plist") }
        let akdInfo = try plist(akd.data.bytes(at: info.offset, size: info.size))
        guard let marker = kernel.range(of: Data("Darwin Kernel Version ".utf8)) else { throw AnisetteError("No kernel version") }
        let tail = String(decoding: kernel[marker.upperBound..<min(kernel.count, marker.upperBound + 32)], as: UTF8.self)
        guard let darwin = tail.split(separator: ":", maxSplits: 1).first, darwin.wholeMatch(of: /[0-9]+\.[0-9]+\.[0-9]+/) != nil
        else { throw AnisetteError("Invalid kernel version") }
        return try AnisetteSystemInfo(
            productVersion: field("ProductVersion", in: system), buildVersion: field("ProductBuildVersion", in: system),
            darwinVersion: String(darwin), cfNetworkVersion: field("CFBundleVersion", in: cfNetwork),
            authKitVersion: field("CFBundleVersion", in: authKit), akdVersion: field("CFBundleShortVersionString", in: akdInfo))
    }

    static func plist(_ data: Data) throws -> [String: Any] {
        guard let plist = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
            throw AnisetteError("Expected a property-list dictionary")
        }
        return plist
    }

    private static func field(_ key: String, in plist: [String: Any]) throws -> String {
        guard let value = plist[key] as? String else { throw AnisetteError("Missing \(key)") }
        return value
    }

    static func localAssets() throws -> [String: Data] {
        guard let directory = ProcessInfo.processInfo.environment["ANISETTE_APPLE_DIR"] else {
            throw AnisetteError("Set ANISETTE_APPLE_DIR to the verified Apple assets")
        }
        return try Resources.readAssets(URL(fileURLWithPath: directory))
    }
}

struct ProfileGenerationTests {
    static let environment = ProcessInfo.processInfo.environment

    /// Offline half of a rotation: entries come from the cached images alone, and the checked-in
    /// shared-cache tables name exactly the pinned imports at addresses the image actually holds.
    @Test(.enabled(if: environment["ANISETTE_APPLE_DIR"] != nil))
    func checkedInProfileMatchesImages() throws {
        let assets = try ProfileGeneration.localAssets()
        let configuration = try Profile.Configuration.load()
        let entries = try ProfileGeneration.entries(assets, kernelCollectionBase: configuration.build.kernelCollectionBase)
        #expect(entries == configuration.entries)
        let services = try ProfileGeneration.image("AppleMediaServices", assets)
        #expect(Set(configuration.functions.values) == Set(ProfileGeneration.Pinned.functions))
        #expect(Set(configuration.slots.values) == Set(ProfileGeneration.Pinned.slots))
        let pointers = try ProfileGeneration.dataPointers(services)
        #expect(configuration.functions.keys.allSatisfy { UInt64($0).map(pointers.contains) == true })
        let slots = try ProfileGeneration.externalSlots(services)
        #expect(configuration.slots.keys.allSatisfy { UInt64($0).map(slots.contains) == true })
    }
}
#endif
