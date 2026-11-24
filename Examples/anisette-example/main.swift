import Anisette
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

// Provisions a virtual Mac identity with Apple on first run, then prints anisette headers.
// Usage: swift run anisette-example [identity.json]

struct Identity: Codable {
    var identifier: UUID
    var routingInfo: UInt64
    var provisioningState: Data
}

struct ExampleError: Error, CustomStringConvertible { let description: String }

let identityFile = URL(fileURLWithPath: CommandLine.arguments.dropFirst().first ?? "anisette-identity.json")

func save(_ identity: Identity) throws {
    try JSONEncoder().encode(identity).write(to: identityFile, options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: identityFile.path)
}

func log(_ message: String) { FileHandle.standardError.write(Data((message + "\n").utf8)) }

// First use fetches Unicorn and parts of Apple's restore image; report each request as it happens.
let configuration = AnisetteConfiguration(httpClient: AnisetteHTTPClient { url, range in
    log("Downloading \(url.lastPathComponent)" + (range.map { " (\($0.count) bytes)" } ?? ""))
    return try await AnisetteHTTPClient.live.fetch(url, range)
})

let system = try AnisetteSystemInfo.current()

func appleRequest(_ url: URL, identifier: UUID, body: [String: Any]? = nil) async throws -> [String: Any] {
    var request = URLRequest(url: url)
    request.setValue(system.akdUserAgent, forHTTPHeaderField: "User-Agent")
    for (name, value) in system.deviceHeaders(identifier: identifier) {
        request.setValue(value, forHTTPHeaderField: name)
    }
    if let body {
        request.httpMethod = "POST"
        request.setValue("text/x-xml-plist", forHTTPHeaderField: "Content-Type")
        request.httpBody = try PropertyListSerialization.data(fromPropertyList: ["Header": [String: Any](), "Request": body],
                                                              format: .xml, options: 0)
    }
    let (data, response) = try await URLSession.shared.data(for: request)
    let status = (response as? HTTPURLResponse)?.statusCode ?? 0
    guard status == 200, let plist = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
        throw ExampleError(description: "\(url.absoluteString) returned HTTP \(status)")
    }
    return body == nil ? plist : try field("Response", in: plist) { $0 as? [String: Any] }
}

func field<T>(_ name: String, in plist: [String: Any], _ parse: (Any) -> T?) throws -> T {
    guard let value = plist[name].flatMap(parse) else { throw ExampleError(description: "Apple's reply has no valid \(name)") }
    return value
}

func string<T>(_ name: String, in plist: [String: Any], _ parse: (String) -> T?) throws -> T {
    try field(name, in: plist) { ($0 as? String).flatMap(parse) }
}

func provision(_ identifier: UUID) async throws -> Identity {
    let lookup = try await appleRequest(URL(string: "https://gsa.apple.com/grandslam/GsService2/lookup")!, identifier: identifier)
    let urls = try field("urls", in: lookup) { $0 as? [String: Any] }
    let start = try await appleRequest(string("midStartProvisioning", in: urls, URL.init), identifier: identifier, body: [:])
    let serverChallenge = try string("spim", in: start) { Data(base64Encoded: $0) }
    var routingInfo: UInt64 = 0
    let state = try await AnisetteContext.provision(
        identifier: identifier,
        challenge: serverChallenge,
        configuration: configuration
    ) { clientChallenge in
        let finish = try await appleRequest(string("midFinishProvisioning", in: urls, URL.init), identifier: identifier,
                                            body: ["cpim": clientChallenge.base64EncodedString()])
        routingInfo = try string("X-Apple-I-MD-RINFO", in: finish) { UInt64($0) }
        let metadata = try string("ptm", in: finish) { Data(base64Encoded: $0) }
        let trustKey = try string("tk", in: finish) { Data(base64Encoded: $0) }
        return (metadata, trustKey)
    }
    return Identity(identifier: identifier, routingInfo: routingInfo, provisioningState: state)
}

var identity: Identity
if let saved = try? Data(contentsOf: identityFile) {
    identity = try JSONDecoder().decode(Identity.self, from: saved)
    log("Using the identity in \(identityFile.path)")
} else {
    log("Provisioning a new identity")
    identity = try await provision(UUID())
    try save(identity)
}

let otp = try await AnisetteContext.with(identifier: identity.identifier, provisioningState: identity.provisioningState,
                                         configuration: configuration) { try await $0.requestOTP() }
identity.provisioningState = otp.provisioningState
try save(identity)

let headers = otp.headers(identifier: identity.identifier, routingInfo: identity.routingInfo, system: system)
for (name, value) in headers.sorted(by: { $0.key < $1.key }) { print("\(name): \(value)") }
