import Foundation

extension GuestServices {
    func allocate(_ size: UInt64, alignment: UInt64 = 16) throws -> UInt64 {
        try require(size <= GuestMachine.heapSize && alignment > 0 && alignment <= GuestMachine.heapSize
                    && alignment & (alignment - 1) == 0, "Invalid guest allocation")
        let reserved = try guestAligned(max(size, 1), to: alignment)
        if alignment == 16, let index = freeBlocks.firstIndex(where: { $0.upperBound - $0.lowerBound >= reserved }) {
            let block = freeBlocks[index]
            let address = block.lowerBound
            if address + reserved == block.upperBound { freeBlocks.remove(at: index) } else {
                freeBlocks[index] = address + reserved..<block.upperBound
            }
            allocations[address] = Allocation(size: size, reserved: reserved)
            return address
        }
        let cursor = try guestAligned(heapCursor, to: alignment)
        try require(cursor <= GuestMachine.heapSize - reserved, "Guest heap exhausted")
        let address = GuestMachine.heapBase + cursor
        heapCursor = cursor + reserved
        allocations[address] = Allocation(size: size, reserved: reserved)
        return address
    }

    func release(_ address: UInt64) throws {
        guard let allocation = allocations.removeValue(forKey: address) else { throw AnisetteError("Free of unknown guest pointer") }
        try engine.write(address, Data(count: Int(allocation.reserved)))
        // freeBlocks stays sorted and coalesced, so only the neighbours of the insertion point can merge.
        var block = address..<address + allocation.reserved
        var low = 0, high = freeBlocks.count
        while low < high {
            let middle = (low + high) / 2
            if freeBlocks[middle].lowerBound < block.lowerBound { low = middle + 1 } else { high = middle }
        }
        var index = low
        if index < freeBlocks.count, freeBlocks[index].lowerBound == block.upperBound {
            block = block.lowerBound..<freeBlocks.remove(at: index).upperBound
        }
        if index > 0, freeBlocks[index - 1].upperBound == block.lowerBound {
            index -= 1
            block = freeBlocks.remove(at: index).lowerBound..<block.upperBound
        }
        if block.upperBound == GuestMachine.heapBase + heapCursor {
            heapCursor -= block.upperBound - block.lowerBound
        } else {
            freeBlocks.insert(block, at: index)
        }
    }

    // swiftlint:disable cyclomatic_complexity
    func memoryService(_ name: String) throws -> Bool {
        switch name {
        case "malloc", "mallocTypedVariable", "mallocLock", "mallocTyped", "mallocAligned":
            let size: UInt64
            switch name {
            case "mallocLock": size = 8
            case "mallocTypedVariable": size = try argument(1)
            case "mallocTyped": size = UInt64(try engine.read(guestAddress(argument(0), offset: 44), as: UInt32.self) & 0xffffff)
            default: size = try argument(0)
            }
            let address = try allocate(size, alignment: name == "mallocAligned" ? argument(1) : 16)
            if name == "mallocLock" { try engine.write(address, UInt64(0)) }
            try result(address)
        case "mallocGoodSize": try result(guestAligned(max(argument(0), 1)))
        case "mallocSize": try result(allocations[argument(0)]?.reserved ?? 0)
        case "free", "freeTyped":
            let address = try argument(name == "free" ? 0 : 1)
            if address != 0 { try release(address) }
            try result(0)
        case "calloc":
            let count = try argument(0), size = try argument(1)
            try require(count == 0 || size <= UInt64.max / count, "Allocation size overflow")
            let address = try allocate(count * size)
            try engine.write(address, Data(count: Int(count * size)))
            try result(address)
        case "realloc":
            let old = try argument(0), size = try argument(1)
            if old == 0 { try result(allocate(size)); return true }
            guard var allocation = allocations[old] else { throw AnisetteError("Reallocation of unknown guest pointer") }
            if size <= allocation.reserved {
                allocation.size = size; allocations[old] = allocation; try result(old)
            } else {
                let address = try allocate(size)
                try engine.write(address, engine.read(old, allocation.size))
                try release(old)
                try result(address)
            }
        case "mmap", "vmAllocate":
            let size = try argument(name == "mmap" ? 1 : 2)
            let address = try allocate(size, alignment: 4096)
            try engine.write(address, Data(count: Int(size)))
            if name == "vmAllocate" { try engine.write(argument(1), address) }
            try result(name == "mmap" ? address : 0)
        case "munmap", "vmDeallocate":
            let address = try argument(name == "munmap" ? 0 : 1)
            do { try release(address); try result(0) } catch {
                try result(name == "munmap" ? .max : 1)
            }
        case "memmove", "checkedMemcpy":
            let destination = try argument(0), source = try argument(1), size = try argument(2)
            if name == "checkedMemcpy" { try require(size <= argument(3), "Checked copy exceeds buffer") }
            try engine.write(destination, engine.read(source, size))
            try result(destination)
        case "memset", "checkedMemset", "bzero":
            let destination = try argument(0)
            let size = try argument(name == "bzero" ? 1 : 2)
            let byte = try name == "bzero" ? UInt8(0) : UInt8(truncatingIfNeeded: argument(1))
            if name == "checkedMemset" { try require(size <= argument(3), "Checked fill exceeds buffer") }
            try require(size <= 64 << 20, "Guest fill exceeds limit")
            try engine.write(destination, Data(repeating: byte, count: Int(size)))
            try result(destination)
        case "memcmp", "strcmp", "strncmp":
            let left = try argument(0), right = try argument(1)
            let count = try name == "strcmp" ? UInt64(4096) : argument(2)
            try require(count <= 64 << 20, "Guest comparison exceeds limit")
            var comparison: Int64 = 0
            if name == "memcmp" {
                let a = try engine.read(left, count), b = try engine.read(right, count)
                if a != b { comparison = a.lexicographicallyPrecedes(b) ? -1 : 1 }
            } else {
                // Read page-bounded chunks so neither string is read past the page holding its terminator.
                var offset: UInt64 = 0
                compare: while offset < count {
                    let leftAddress = try guestAddress(left, offset: offset)
                    let rightAddress = try guestAddress(right, offset: offset)
                    let length = min(count - offset, 4096 - leftAddress % 4096, 4096 - rightAddress % 4096)
                    let a = try engine.read(leftAddress, length), b = try engine.read(rightAddress, length)
                    for (x, y) in zip(a, b) {
                        if x != y { comparison = Int64(x) - Int64(y); break compare }
                        if x == 0 { break compare }
                    }
                    offset += length
                }
            }
            try result(UInt64(bitPattern: comparison))
        case "strlen": try result(UInt64(string(argument(0)).utf8.count))
        case "strnlen":
            let address = try argument(0), limit = try argument(1)
            try require(limit <= 64 << 20, "Guest string exceeds limit")
            var length: UInt64 = 0
            while length < limit {
                let current = try guestAddress(address, offset: length)
                let count = min(limit - length, 4096 - current % 4096)
                let chunk = try engine.read(current, count)
                if let zero = chunk.firstIndex(of: 0) { length += UInt64(zero); break }
                length += count
            }
            try result(length)
        default: return false
        }
        return true
    }
    // swiftlint:enable cyclomatic_complexity
}
