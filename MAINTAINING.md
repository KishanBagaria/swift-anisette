# Maintaining

All Apple and Unicorn inputs are pinned. `.github/workflows/upstream-check.yml` checks weekly that the pinned downloads still exist:

```sh
ANISETTE_TEST_UPSTREAM=1 swift test --filter UpstreamTests
```

## Rotating the Apple build

```sh
make rotate                  # Apple's latest release
make rotate IPSW=<ipsw url>  # a specific UniversalMac restore image
```

Everything that names the Apple build lives in `Sources/Anisette/Resources/Profile.json`, and `make rotate` regenerates that file; nothing else changes. It runs `rotateBuild` in `Tests/AnisetteTests/BuildRotation.swift`, which:

1. finds the restore image (Apple's catalog, unless `IPSW` is given) and its size;
2. reads the build manifest for the disk images that go with the kernel cache, and records each member's name and sizes;
3. extracts the assets and records their sizes and SHA-256 values;
4. derives the profile: entries, shared-cache functions and slots, system versions (see [Profile inputs](#profile-inputs));
5. starts ADI on the result and requires its not-provisioned status for an OTP request, and only then writes `Profile.json`.

`make rotate` then runs the whole suite against the extracted assets, kept in `.build/rotation-assets`, and checks that the restore image is reachable at the pinned size. Review the diff of `Profile.json` and commit it.

If a step throws, the build no longer fits an assumption below. Nothing has been written at that point; fix the input and run it again.

## Profile inputs

Addresses are derived from the binaries: the shared-cache functions and slots by binding AppleMediaServices' imports against the dyld cache's export tries, the daemon entries from `LC_MAIN`, and the kernel entries from FairPlayIOKit's symbol table. `ProfileGeneration.Pinned` holds the names that have no structure to derive them from.

- **commerce ADI functions** (`startProvisioning`, `endProvisioning`, `requestOTP`). commerce links ADI statically and strips it, so they are found through their only callers, two `ADIController` methods named in `Pinned`. The provisioning method and its blocks call start (`dsid, challenge, length, &clientChallenge, &length, &session`), a buffer free, then end (`session, metadata, length, trustKey, length`). The strings method calls the OTP function (`dsid, &mid, &length, &otp, &length`), then the same buffer free. `ProfileGeneration.commerceEntries` takes the functions from that call order and throws if either method has another shape. To re-derive by hand, find the IMPs with `otool -ov commerce`, then the `bl` targets inside `__text`, and compare with the previous build's binary.
- **FairPlayIOKit symbols.** The kext keeps local symbols, named in `Pinned.Kernel`: its start routine, setup, init (which returns the session context), the message handler and `___chkstk_darwin`. The obfuscated names may change with a build; `nm -n` near the old addresses shows the new ones. `kernelStackProbe` is derived: the `__DATA_CONST,__auth_ptr` slot that points to `___chkstk_darwin`.
- **Shared-cache functions.** AppleMediaServices' obfuscated code calls libSystem, CoreFoundation and IOKit through a table of function pointers in `__AUTH_CONST,__const`. Only the subset observed while running the upstream SAP signer is prelinked (see README.md for provenance). The tested ADI paths never execute AppleMediaServices code, so the list is kept as is rather than re-derived.
- **Shared-cache slots.** `___stack_chk_guard` and `___chkstk_darwin`, which the code loads through GOT slots outside the image (`adrp; ldr` and `adrp; add; ldr; braa`).
- **Kernel cache.** `BuildRotation.kernelCacheName` picks which device's kernel cache supplies FairPlayIOKit.

## Bumping Unicorn

`Sources/Anisette/UnicornArtifact.swift` pins one PyPI wheel per platform. For each, take the `url` and `sha256` digest from `https://pypi.org/pypi/unicorn/<version>/json` as `url` and `archiveHash`. Set `libraryHash` to the SHA-256 of `unicorn/lib/<name>` inside the wheel. Update the version in `relativePath`. `Sources/CAnisette/unicorn.c` accepts one major and minor version, so a different one needs that check and the ABI reviewed. CI caches Unicorn with the Apple assets, keyed on this file and `Profile.json`. Verify with:

```sh
ANISETTE_TEST_UNICORN=1 swift test --filter nativeUnicornArchiveDownload
ANISETTE_TEST_UPSTREAM=1 swift test --filter UpstreamTests
```

## Third-party licenses

When updating dependencies, refresh the bundled `LICENSE.*` and `NOTICE.*` files, including notices embedded in vendored code.
