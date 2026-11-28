import Foundation

/// Detects heterogeneous ARM64 Linux CPU topologies (big.LITTLE / DynamIQ) and selects the fastest
/// homogeneous CPU cluster so KVM vCPUs stay pinned to identical microarchitecture cores.
enum ARM64CPUTopology {
    struct CPUInfo: Equatable, Sendable {
        let id: Int
        let midr: UInt64?
        let capacity: UInt64?
        let maxFreqKHz: UInt64?
    }

    /// Mask keeping `MIDR_EL1` Implementer (`[31:24]`) and PartNum (`[15:4]`), ignoring stepping.
    static let midrPartMask: UInt64 = 0xff00_fff0

    /// Parses Linux sysfs CPU range lists such as `"0-3,4-7"` or `"0,2,4-5"`.
    static func parseCPUList(_ text: String) -> [Int] {
        var result: Set<Int> = []
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return [] }
        for token in trimmed.split(separator: ",") {
            let part = token.trimmingCharacters(in: .whitespaces)
            if let dash = part.firstIndex(of: "-") {
                let startText = part[..<dash]
                let endText = part[part.index(after: dash)...]
                guard let start = Int(startText), let end = Int(endText), start >= 0, start <= end else {
                    continue
                }
                for cpu in start...end { result.insert(cpu) }
            } else if let cpu = Int(part), cpu >= 0 {
                result.insert(cpu)
            }
        }
        return result.sorted()
    }

    /// Parses a decimal or `0x`-prefixed hexadecimal unsigned integer from a sysfs attribute file.
    static func parseSysfsInteger(_ text: String) -> UInt64? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        if trimmed.hasPrefix("0x") || trimmed.hasPrefix("0X") {
            return UInt64(trimmed.dropFirst(2), radix: 16)
        }
        return UInt64(trimmed, radix: 10)
    }

    /// Selects the fastest homogeneous cluster from `cpus`, or returns `nil` when the host is
    /// homogeneous (or topology information cannot distinguish clusters).
    static func preferredCluster(from cpus: [CPUInfo]) -> [Int]? {
        guard cpus.count > 1 else { return nil }
        let groups: [UInt64: [CPUInfo]]
        if cpus.allSatisfy({ $0.midr != nil }) {
            groups = Dictionary(grouping: cpus) { ($0.midr ?? 0) & midrPartMask }
        } else if cpus.allSatisfy({ $0.capacity != nil }) {
            groups = Dictionary(grouping: cpus) { $0.capacity ?? 0 }
        } else if cpus.allSatisfy({ $0.maxFreqKHz != nil }) {
            groups = Dictionary(grouping: cpus) { $0.maxFreqKHz ?? 0 }
        } else {
            return nil
        }
        guard groups.count > 1 else { return nil }

        let best = groups.values.max { lhs, rhs in
            compareClusters(lhs, rhs)
        }
        return best?.map(\.id).sorted()
    }

    /// Reads Linux sysfs under `sysfsRoot` (`/sys/devices/system/cpu`) and returns the fastest
    /// homogeneous cluster for pinning, or `nil` when pinning is unnecessary.
    static func detectPreferredCluster(
        sysfsRoot: URL = URL(fileURLWithPath: "/sys/devices/system/cpu")
    ) -> [Int]? {
        let ids = discoverCPUIndices(in: sysfsRoot)
        guard ids.count > 1 else { return nil }
        let infos = ids.map { id -> CPUInfo in
            let cpuDir = sysfsRoot.appendingPathComponent("cpu\(id)")
            let midr = readInteger(cpuDir.appendingPathComponent("regs/identification/midr_el1"))
            let capacity = readInteger(cpuDir.appendingPathComponent("cpu_capacity"))
            let maxFreq = readInteger(cpuDir.appendingPathComponent("cpufreq/cpuinfo_max_freq"))
            return CPUInfo(id: id, midr: midr, capacity: capacity, maxFreqKHz: maxFreq)
        }
        return preferredCluster(from: infos)
    }

    private static func compareClusters(_ lhs: [CPUInfo], _ rhs: [CPUInfo]) -> Bool {
        let lhsCapacity = lhs.compactMap(\.capacity).max() ?? 0
        let rhsCapacity = rhs.compactMap(\.capacity).max() ?? 0
        if lhsCapacity != rhsCapacity { return lhsCapacity < rhsCapacity }

        let lhsFreq = lhs.compactMap(\.maxFreqKHz).max() ?? 0
        let rhsFreq = rhs.compactMap(\.maxFreqKHz).max() ?? 0
        if lhsFreq != rhsFreq { return lhsFreq < rhsFreq }

        if lhs.count != rhs.count { return lhs.count < rhs.count }

        let lhsMaxID = lhs.map(\.id).max() ?? -1
        let rhsMaxID = rhs.map(\.id).max() ?? -1
        return lhsMaxID < rhsMaxID
    }

    private static func discoverCPUIndices(in sysfsRoot: URL) -> [Int] {
        let onlineURL = sysfsRoot.appendingPathComponent("online")
        if let text = try? String(contentsOf: onlineURL, encoding: .utf8) {
            let parsed = parseCPUList(text)
            if !parsed.isEmpty { return parsed }
        }
        guard let names = try? FileManager.default.contentsOfDirectory(atPath: sysfsRoot.path) else {
            return []
        }
        return names.compactMap { name -> Int? in
            guard name.hasPrefix("cpu"), let id = Int(name.dropFirst(3)), id >= 0 else { return nil }
            return id
        }.sorted()
    }

    private static func readInteger(_ url: URL) -> UInt64? {
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return nil }
        return parseSysfsInteger(text)
    }
}
