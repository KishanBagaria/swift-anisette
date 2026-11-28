SWIFTLINT ?= swiftlint
# A restore image URL for `make rotate`; Apple's latest release when unset.
IPSW ?= latest
ROTATION_ASSETS = $(CURDIR)/.build/rotation-assets

.PHONY: test test-hypervisor lint rotate
test:
	swift test

# Ad-hoc signs the Swift Testing runner with com.apple.security.hypervisor and runs the suite.
# Pass FILTER=... to run matching tests (e.g., `make test-hypervisor FILTER=HypervisorTests`).
test-hypervisor:
	./Support/test-hypervisor.sh $(if $(FILTER),--filter "$(FILTER)")

lint:
	$(SWIFTLINT) lint --strict

# Regenerates Sources/Anisette/Resources/Profile.json from a restore image, then runs every test
# against the assets it extracted. See MAINTAINING.md.
rotate:
	ANISETTE_ROTATE=$(IPSW) ANISETTE_APPLE_DIR=$(ROTATION_ASSETS) swift test --filter rotateBuild
	ANISETTE_APPLE_DIR=$(ROTATION_ASSETS) swift test
	ANISETTE_TEST_UPSTREAM=1 swift test --filter pinnedRestoreImageIsAvailable
