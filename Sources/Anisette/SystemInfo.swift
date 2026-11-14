import Foundation

/// Version metadata extracted from the pinned restore image by the profile generator.
/// This describes the virtual Mac, independently of the host running Unicorn.
public struct AnisetteSystemInfo: Codable, Sendable {
    let productVersion: String
    let buildVersion: String
    let darwinVersion: String
    let cfNetworkVersion: String
    let authKitVersion: String
    let akdVersion: String

    // The model is part of the virtual hardware identity, rather than the host's model.
    var model: String { "MacBookPro13,3" }

    public static func current() throws -> Self {
        try Profile.Configuration.load().system
    }

    public var clientInfo: String {
        "<\(model)> <Mac OS X;\(productVersion);\(buildVersion)> "
            + "<com.apple.AuthKit/\(authKitVersion) (com.apple.akd/\(akdVersion))>"
    }

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
