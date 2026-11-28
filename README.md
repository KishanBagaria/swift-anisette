# swift-anisette

Local anisette generation in Swift for macOS and Linux. Runs Apple's ADI natively via `Hypervisor.framework` on Apple Silicon macOS or `/dev/kvm` on ARM64 Linux, falling back to Unicorn elsewhere.

Requires Swift 6.2 or later. iOS is not supported.

## Installation

Add the package to `Package.swift` and depend on `.product(name: "Anisette", package: "swift-anisette")`:

```swift
.package(url: "https://github.com/KishanBagaria/swift-anisette", from: "0.1.0")
```

- **macOS (Apple Silicon):** Add `com.apple.security.hypervisor` to run natively via `Hypervisor.framework` without downloading Unicorn. Otherwise (and on Intel Macs) it falls back to Unicorn, which on hardened apps requires `com.apple.security.cs.allow-unsigned-executable-memory` and `com.apple.security.cs.disable-library-validation`.
- **Linux:** Requires zlib headers (`zlib1g-dev` on Ubuntu). On ARM64 hosts with `/dev/kvm` access it runs natively via KVM without downloading Unicorn; otherwise it falls back to Unicorn.

## Example

[Examples/anisette-example](Examples/anisette-example/main.swift) provisions an identity with Apple (no Apple ID required) and prints anisette headers:

```sh
git clone https://github.com/KishanBagaria/swift-anisette && cd swift-anisette
swift run anisette-example
```

## Usage

Generate an OTP and build headers for a provisioned identity:

```swift
import Foundation
import Anisette

let otp = try await AnisetteContext.with(
    identifier: stableDeviceUUID,
    provisioningState: savedProvisioningState
) { context in
    try await context.requestOTP()
}
// Persist otp.provisioningState before using this identity again.

let headers = otp.headers(
    identifier: stableDeviceUUID,
    routingInfo: savedRoutingInfo,
    system: try AnisetteSystemInfo.current()
)
```

Provision a new identity by exchanging challenges with Apple's servers (see [Examples/anisette-example](Examples/anisette-example/main.swift)):

```swift
let state = try await AnisetteContext.provision(
    identifier: stableDeviceUUID,
    challenge: serverChallenge
) { clientChallenge in
    try await sendToApple(clientChallenge)
}
```

Keep each identity's UUID stable and serialize its read → generate → persist cycle. For split provisioning or long-lived contexts, see `startProvisioning(challenge:)` and `open(identifier:provisioningState:)` in [Anisette.swift](Sources/Anisette/API/Anisette.swift).

## Runtime

First use extracts required Apple binaries (~215 MB fetched via range requests, ~90 MB cached under `swift-anisette` in the user's cache directory, plus Unicorn if the fallback backend is used). Call `AnisetteContext.prepare(configuration:)` to warm the cache ahead of time.

Pass `AnisetteConfiguration` to customize `cacheDirectory`, offline paths (`appleDirectory`, `unicornLibrary`), `backend` (`.automatic`, `.hypervisor`, `.kvm`, `.unicorn`), or `httpClient`.

## License

[MIT](LICENSE.md). Third-party notices are in [Resources](Sources/Anisette/Resources). The optional Unicorn fallback is GPLv2; Apple assets retain Apple's terms.
