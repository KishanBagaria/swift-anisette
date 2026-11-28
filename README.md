# swift-anisette

Local anisette generation in Swift for macOS and Linux. Runs Apple's ADI implementation natively via `Hypervisor.framework` on entitled Apple Silicon Macs or `/dev/kvm` on ARM64 Linux, falling back to Unicorn elsewhere. The caller handles provisioning HTTP requests and stores the resulting state; Apple ID credentials stay with the caller.

Requires Swift 6.2 or later. iOS is not supported.

## Installation

```swift
.package(url: "https://github.com/KishanBagaria/swift-anisette", from: "0.1.0")
```

Add `.product(name: "Anisette", package: "swift-anisette")` to your target's dependencies.

Linux needs zlib development headers (`zlib1g-dev` on Ubuntu). On ARM64 Linux hosts where `/dev/kvm` is accessible, the library uses KVM by default and avoids downloading Unicorn; otherwise it falls back to Unicorn. Apple Silicon macOS apps with `com.apple.security.hypervisor` use `Hypervisor.framework` by default and avoid downloading Unicorn; without it (e.g., unsigned CLI runs or non-nested CI VMs) and on Intel Macs, the library falls back to Unicorn, which on hardened macOS apps requires `com.apple.security.cs.allow-unsigned-executable-memory` and `com.apple.security.cs.disable-library-validation`.

## Example

[Examples/anisette-example](Examples/anisette-example/main.swift) provisions a new identity with Apple, saves it, and prints the anisette headers. It needs no Apple ID:

```sh
git clone https://github.com/KishanBagaria/swift-anisette && cd swift-anisette
swift run anisette-example
```

Run it again to reuse the identity saved in `anisette-identity.json`.

## Usage

For an already provisioned identity:

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
// otp.machineID and otp.password contain the anisette data.
```

For a new identity, exchange the challenges with Apple's servers; the example implements `sendToApple`. `AnisetteContext.provision` opens a dedicated context, passes the client challenge (`cpim`) to your closure, finishes with Apple's reply (`ptm` and `tk`), and returns the new provisioning state:

```swift
let state = try await AnisetteContext.provision(
    identifier: stableDeviceUUID,
    challenge: serverChallenge
) { clientChallenge in
    try await sendToApple(clientChallenge)
}
// Save state, then:
let otp = try await AnisetteContext.with(identifier: stableDeviceUUID, provisioningState: state) { context in
    try await context.requestOTP()
}
```

For split provisioning flows, call `startProvisioning(challenge:)` on an open context to get a `ProvisioningSession` holding `clientChallenge`, then call `session.finish(metadata:trustKey:)`. `finish` ends the context's runtime whether it succeeds or throws, so request OTPs from a second context opened with the returned state. Afterwards every call on the first context throws `AnisetteError`. While a session is open, `requestOTP()` and another `startProvisioning` throw; close the context to abandon it. If ADI rejects the server challenge, `startProvisioning` throws with `adiStatus` set and the context stays usable.

`otp.headers(identifier:routingInfo:system:)` builds the anisette request headers (`X-Apple-I-MD`, `X-Apple-I-MD-M`, `X-Apple-I-MD-RINFO`, `X-Apple-I-MD-LU`, `X-Mme-Device-Id`, `X-MMe-Client-Info`, `X-Apple-I-SRL-NO`, `X-Apple-I-Client-Time`, `X-Apple-I-TimeZone`, `X-Apple-Locale`), defaulting `date`, `timeZone`, and `locale` to `Date()`, `.current`, and `.current`. `routingInfo` is the `X-Apple-I-MD-RINFO` value Apple returns when provisioning finishes, which the caller stores with the state; `system` is normally `AnisetteSystemInfo.current()`. Use `system.deviceHeaders(identifier:)` for Apple requests that need the device headers without an OTP (such as provisioning).

`open(identifier:provisioningState:)` and `close()` remain available for contexts that must outlive a single scope.

Keep each identity's UUID stable and serialize its entire read → generate → persist transaction.

## Runtime

First use extracts the required files from Apple's public restore image (and downloads Unicorn when Unicorn is used). This fetches about 215 MB in ranged requests, takes a few minutes, and keeps about 90 MB. Downloads are verified and cached in the user's cache directory under `swift-anisette`. Call `AnisetteContext.prepare(configuration:)` at startup to pre-warm and verify the runtime without opening a context. Nothing is logged meanwhile; wrap `AnisetteHTTPClient.live` in your own `httpClient` to report progress, as the example does.

Pass an `AnisetteConfiguration` to `prepare`, `open`, `with`, or `provision` for a custom cache (`cacheDirectory`), offline assets (`appleDirectory`, `unicornLibrary`), execution `backend` (`.automatic`, `.hypervisor`, `.kvm`, or `.unicorn`), or your own downloader (`httpClient`). `unicornLibrary` is only used when running on Unicorn.

```swift
let configuration = AnisetteConfiguration(cacheDirectory: appSupport.appendingPathComponent("anisette"))
try await AnisetteContext.with(identifier: id, provisioningState: state, configuration: configuration) { ... }
```

## Errors

The library throws `AnisetteError` (conforming to `LocalizedError`), or `CancellationError` when the task is cancelled or the context is closed. When Apple's ADI rejects a call, `adiStatus` holds its status code; `AnisetteError.notProvisionedStatus` means the identity must be provisioned first.

## Development

Run `swift test`, `make test-hypervisor` (ad-hoc signs the test runner with `com.apple.security.hypervisor`), and `make lint`. Network and cached-runtime checks are opt-in. `ANISETTE_APPLE_DIR` names a directory of verified Apple assets; the installer test fills it when set, and also caches Unicorn when needed. `ANISETTE_UNICORN_LIBRARY` optionally points at libunicorn instead. The cached-runtime tests never fetch Apple assets; their only permitted download is the pinned Unicorn wheel, when Unicorn is used and no library is named or cached.

```sh
export ANISETTE_APPLE_DIR=~/Library/Caches/swift-anisette/test-assets
ANISETTE_TEST_ASSETS=1 swift test --filter nativeAssetInstallation
swift test --filter AnisetteTests
make test-hypervisor
ANISETTE_TEST_UNICORN=1 swift test --filter nativeUnicornArchiveDownload
```

`make rotate` moves the pinned Apple build to Apple's latest release. See [MAINTAINING.md](MAINTAINING.md) for that and for bumping Unicorn.

## License

[MIT](LICENSE.md). Third-party licenses and attributions are bundled in [Resources](Sources/Anisette/Resources). When Unicorn is used, the downloaded Unicorn runtime is GPLv2; Apple assets retain Apple's terms.
