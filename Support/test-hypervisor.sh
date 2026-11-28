#!/bin/sh
set -eu

ENTITLEMENTS="$(cd "$(dirname "$0")" && pwd)/hypervisor.entitlements"
swift build --build-tests ${SWIFT_BUILD_FLAGS:-}
BIN_PATH="$(swift build --show-bin-path ${SWIFT_BUILD_FLAGS:-})"
# SwiftPM's native build system names the bundle after the package; the swiftbuild system names it after the test target.
for BUNDLE in swift-anisettePackageTests AnisetteTests; do
    TEST_BIN="$BIN_PATH/$BUNDLE.xctest/Contents/MacOS/$BUNDLE"
    [ -f "$TEST_BIN" ] && break
done
[ -f "$TEST_BIN" ] || { echo "No test bundle found in $BIN_PATH" >&2; exit 1; }
SWIFT_BIN="$(xcrun --find swift)"
TOOLCHAIN="$(cd "$(dirname "$SWIFT_BIN")/.." && pwd)"
HELPER_SRC="$TOOLCHAIN/libexec/swift/pm/swiftpm-testing-helper"
HELPER_DST="$BIN_PATH/swiftpm-testing-helper-hypervisor"
PLATFORM_DEVELOPER="$(xcrun --show-sdk-platform-path)/Developer"

cp "$HELPER_SRC" "$HELPER_DST"
codesign --force --sign - --entitlements "$ENTITLEMENTS" "$HELPER_DST"
exec env DYLD_FRAMEWORK_PATH="$PLATFORM_DEVELOPER/Library/Frameworks:$TOOLCHAIN/lib/swift/macosx${DYLD_FRAMEWORK_PATH:+:$DYLD_FRAMEWORK_PATH}" \
    DYLD_LIBRARY_PATH="$PLATFORM_DEVELOPER/usr/lib${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}" \
    "$HELPER_DST" --test-bundle-path "$TEST_BIN" --testing-library swift-testing "$@"
