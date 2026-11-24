import Foundation

extension Data {
    func virtualFileBytes(offset: Int, count: Int) throws -> Data {
        try require(offset >= 0 && offset <= self.count && count >= 0, "Invalid virtual file offset")
        let length = Swift.min(count, self.count - offset)
        let start = index(startIndex, offsetBy: offset)
        return Data(self[start..<index(start, offsetBy: length)])
    }
}

private enum OpenFlags {
    static let creat: Int32 = 0x200
    static let trunc: Int32 = 0x400
}

private enum StatLayout {
    static let size = 144
    static let modeOffset: UInt64 = 4
    static let sizeOffset: UInt64 = 96
    static let fileMode: UInt16 = 0x8180
    static let dirMode: UInt16 = 0x41ed
}

extension GuestServices {
    // swiftlint:disable cyclomatic_complexity
    func fileService(_ name: String) throws -> Bool {
        switch name {
        case "open":
            let path = try string(argument(0)), flags = try signedArgument32(1)
            if path == "/var/db" || path == "/var/setup" { try result(4) } else if path == ADIRuntime.statePath {
                guard files[path] != nil || flags & OpenFlags.creat != 0 else { try result(.max); return true }
                if files[path] == nil || flags & OpenFlags.trunc != 0 { files[path] = Data() }
                filePath = path; fileOffset = 0; try result(5)
            } else if path == "./../CoreFP.icxs" { icxsOffset = 0; try result(3) } else { try result(.max) }
        case "lstat":
            let path = try string(argument(0))
            let isFile = path == ADIRuntime.statePath && files[path] != nil
            guard isFile || ["/var/db/fpsd/adi", "/var/db", "/var/setup"].contains(path) else {
                try result(.max); return true
            }
            try engine.write(guestAddress(argument(1), offset: StatLayout.modeOffset),
                             isFile ? StatLayout.fileMode : StatLayout.dirMode)
            try result(0)
        case "fstat":
            guard try signedArgument32(0) == 5 else { try result(.max); return true }
            let address = try argument(1)
            try engine.write(address, Data(count: StatLayout.size))
            try engine.write(guestAddress(address, offset: StatLayout.modeOffset), StatLayout.fileMode)
            try engine.write(guestAddress(address, offset: StatLayout.sizeOffset), UInt64(files[filePath]?.count ?? 0))
            try result(0)
        case "ftruncate":
            guard try signedArgument32(0) == 5 && argument(1) <= 1 << 20 else { try result(.max); return true }
            let length = Int(try argument(1))
            var data = files[filePath] ?? Data()
            if length < data.count { data = Data(data.prefix(length)) } else { data.append(Data(count: length - data.count)) }
            files[filePath] = data; fileOffset = min(fileOffset, length); try result(0)
        case "read":
            let descriptor = try signedArgument32(0), address = try argument(1), count = try argument(2)
            try require(count <= 64 << 20, "Guest file read exceeds limit")
            guard descriptor == 3 || descriptor == 5 else { try result(.max); return true }
            let data = descriptor == 3 ? icxs : files[filePath] ?? Data()
            let offset = descriptor == 3 ? icxsOffset : fileOffset
            let bytes = try data.virtualFileBytes(offset: offset, count: Int(count))
            let size = bytes.count
            try engine.write(address, bytes)
            if descriptor == 3 { icxsOffset += size } else { fileOffset += size }
            try result(UInt64(size))
        case "write":
            guard try signedArgument32(0) == 5 else { try result(.max); return true }
            let count = try argument(2)
            try require(count <= 1 << 20 && fileOffset <= (1 << 20) - Int(count), "ADI state exceeds limit")
            let data = try engine.read(argument(1), count)
            var file = files[filePath] ?? Data()
            let end = fileOffset + data.count
            if end > file.count { file.append(Data(count: end - file.count)) }
            file.replaceSubrange(fileOffset..<end, with: data)
            files[filePath] = file; fileOffset = end; try result(count)
        case "unlink":
            let path = try string(argument(0))
            if path == ADIRuntime.statePath {
                files.removeValue(forKey: path); fileOffset = 0; try result(0)
            } else { try result(.max) }
        case "basename":
            let address = try argument(0)
            var path = try string(address)
            while path.hasSuffix("/") { path.removeLast() }
            if let slash = path.utf8.lastIndex(of: UInt8(ascii: "/")) {
                try result(guestAddress(address, offset: UInt64(path.utf8.distance(from: path.utf8.startIndex, to: slash)) + 1))
            } else { try result(address) }
        case "procPIDPath":
            let path = Data("/System/Library/PrivateFrameworks/CommerceKit.framework/Versions/A/Resources/commerce\0".utf8)
            guard try argument(1) != 0 && UInt64(argument32(2)) >= path.count else { try result(.max); return true }
            try engine.write(argument(1), path); try result(UInt64(path.count - 1))
        default: return false
        }
        return true
    }
    // swiftlint:enable cyclomatic_complexity
}
