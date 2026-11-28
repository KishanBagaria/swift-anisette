#if os(macOS) || os(Linux)
import Foundation
import Testing
@testable import Anisette

struct ARM64TopologyTests {
    @Test func cpuTopologyParsesCPUListsAndSysfsIntegers() {
        #expect(ARM64CPUTopology.parseCPUList("0-3,4-7\n") == [0, 1, 2, 3, 4, 5, 6, 7])
        #expect(ARM64CPUTopology.parseCPUList("6-7, 2, 0, 2, bad, 9-5") == [0, 2, 6, 7])
        #expect(ARM64CPUTopology.parseCPUList("").isEmpty)
        #expect(ARM64CPUTopology.parseSysfsInteger("0x00000000410fd0b0\n") == 0x410f_d0b0)
        #expect(ARM64CPUTopology.parseSysfsInteger("1024\n") == 1024)
        #expect(ARM64CPUTopology.parseSysfsInteger("   ") == nil)
    }

    @Test func cpuTopologySelectsFastestClusterAndSkipsHomogeneousHosts() throws {
        // RK3588: 4x Cortex-A55 + 4x Cortex-A76 (two revision steppings, same part number).
        let rk3588: [ARM64CPUTopology.CPUInfo] = [
            .init(id: 0, midr: 0x412f_d050, capacity: 446, maxFreqKHz: 1_800_000),
            .init(id: 1, midr: 0x412f_d050, capacity: 446, maxFreqKHz: 1_800_000),
            .init(id: 2, midr: 0x412f_d050, capacity: 446, maxFreqKHz: 1_800_000),
            .init(id: 3, midr: 0x412f_d050, capacity: 446, maxFreqKHz: 1_800_000),
            .init(id: 4, midr: 0x414f_d0b0, capacity: 1024, maxFreqKHz: 2_400_000),
            .init(id: 5, midr: 0x414f_d0b0, capacity: 1024, maxFreqKHz: 2_400_000),
            .init(id: 6, midr: 0x414f_d0b1, capacity: 1024, maxFreqKHz: 2_400_000),
            .init(id: 7, midr: 0x414f_d0b1, capacity: 1024, maxFreqKHz: 2_400_000),
        ]
        #expect(ARM64CPUTopology.preferredCluster(from: rk3588) == [4, 5, 6, 7])

        // Fallback to cpu_capacity when midr_el1 is unavailable.
        let capacityOnly: [ARM64CPUTopology.CPUInfo] = [
            .init(id: 0, midr: nil, capacity: 512, maxFreqKHz: nil),
            .init(id: 1, midr: nil, capacity: 512, maxFreqKHz: nil),
            .init(id: 2, midr: nil, capacity: 1024, maxFreqKHz: nil),
            .init(id: 3, midr: nil, capacity: 1024, maxFreqKHz: nil),
        ]
        #expect(ARM64CPUTopology.preferredCluster(from: capacityOnly) == [2, 3])

        // Fallback to cpuinfo_max_freq when midr_el1 and cpu_capacity are unavailable.
        let freqOnly: [ARM64CPUTopology.CPUInfo] = [
            .init(id: 0, midr: nil, capacity: nil, maxFreqKHz: 2_200_000),
            .init(id: 1, midr: nil, capacity: nil, maxFreqKHz: 2_200_000),
            .init(id: 2, midr: nil, capacity: nil, maxFreqKHz: 1_500_000),
            .init(id: 3, midr: nil, capacity: nil, maxFreqKHz: 1_500_000),
        ]
        #expect(ARM64CPUTopology.preferredCluster(from: freqOnly) == [0, 1])

        // Homogeneous server (e.g. Graviton / Ampere Altra): no pinning needed.
        let homogeneous = (0..<4).map {
            ARM64CPUTopology.CPUInfo(id: $0, midr: 0x411f_d0c1, capacity: 1024, maxFreqKHz: 2_500_000)
        }
        #expect(ARM64CPUTopology.preferredCluster(from: homogeneous) == nil)
        #expect(ARM64CPUTopology.preferredCluster(from: [homogeneous[0]]) == nil)

        // End-to-end sysfs directory parsing.
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("anisette-sysfs-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: root) }
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try "0-3\n".write(to: root.appendingPathComponent("online"), atomically: true, encoding: .utf8)
        for id in 0..<4 {
            let regs = root.appendingPathComponent("cpu\(id)/regs/identification")
            let freq = root.appendingPathComponent("cpu\(id)/cpufreq")
            try FileManager.default.createDirectory(at: regs, withIntermediateDirectories: true)
            try FileManager.default.createDirectory(at: freq, withIntermediateDirectories: true)
            let midr = id < 2 ? "0x00000000412fd050\n" : "0x00000000414fd0b0\n"
            let cap = id < 2 ? "446\n" : "1024\n"
            let maxFreq = id < 2 ? "1800000\n" : "2400000\n"
            try midr.write(to: regs.appendingPathComponent("midr_el1"), atomically: true, encoding: .utf8)
            try cap.write(to: root.appendingPathComponent("cpu\(id)/cpu_capacity"), atomically: true, encoding: .utf8)
            try maxFreq.write(to: freq.appendingPathComponent("cpuinfo_max_freq"), atomically: true, encoding: .utf8)
        }
        #expect(ARM64CPUTopology.detectPreferredCluster(sysfsRoot: root) == [2, 3])
    }
}
#endif
