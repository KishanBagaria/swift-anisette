import Foundation

/// Version metadata extracted from the pinned restore image by the profile generator.
/// This describes the virtual Mac, independently of the host running Unicorn.
public struct AnisetteSystemInfo: Codable, Equatable, Hashable, Sendable {
    /// The virtual Mac's macOS marketing version (for example `15.4`).
    public let productVersion: String
    /// The virtual Mac's macOS build identifier (for example `24E248`).
    public let buildVersion: String
    /// The virtual Mac's Darwin kernel release version.
    public let darwinVersion: String
    /// The virtual Mac's CFNetwork version, used in `akdUserAgent`.
    public let cfNetworkVersion: String
    /// The virtual Mac's AuthKit version, used in `clientInfo`.
    public let authKitVersion: String
    /// The virtual Mac's `akd` version, used in `clientInfo` and `akdUserAgent`.
    public let akdVersion: String

    /// The virtual Mac's hardware model identifier, independent of the host running Unicorn.
    public var model: String { "MacBookPro13,3" }

    /// Loads the virtual Mac version metadata for the pinned macOS build.
    public static func current() throws -> Self {
        try Profile.Configuration.load().system
    }

    /// The `X-MMe-Client-Info` header value describing this virtual Mac.
    public var clientInfo: String {
        "<\(model)> <Mac OS X;\(productVersion);\(buildVersion)> "
            + "<com.apple.AuthKit/\(authKitVersion) (com.apple.akd/\(akdVersion))>"
    }

    /// The `User-Agent` header value sent by `akd` on this virtual Mac.
    public var akdUserAgent: String {
        "akd/\(akdVersion) CFNetwork/\(cfNetworkVersion) Darwin/\(darwinVersion)"
    }

    func sysctlValue(for name: String) -> String? {
        switch name {
        case "hw.model": model
        case "kern.osversion": buildVersion
        case "kern.osrelease": darwinVersion
        case "kern.osproductversion": productVersion
        case "kern.ostype": "Darwin"
        default: nil
        }
    }
}
