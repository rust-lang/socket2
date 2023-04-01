# Targets available via Rustup that are supported.
# NOTE: keep in sync with the CI and docs.rs targets.
TARGETS ?= "aarch64-apple-ios" "aarch64-linux-android" "x86_64-apple-darwin" "x86_64-unknown-fuchsia" "x86_64-pc-windows-msvc" "x86_64-pc-solaris" "x86_64-unknown-freebsd" "x86_64-unknown-illumos" "x86_64-unknown-linux-gnu" "x86_64-unknown-netbsd" "x86_64-unknown-redox"

test:
	cargo test --all-features

# Test everything for the current OS/architecture and check all targets in
# $TARGETS.
test_all: check_all_targets
	cargo hack test --feature-powerset
	cargo hack test --feature-powerset --release

# Check all targets using all features.
check_all_targets: $(TARGETS)
$(TARGETS):
	cargo hack check --feature-powerset --all-targets --examples --bins --tests --target $@

# Installs all required targets for `check_all_targets`.
install_targets:
	rustup target add $(TARGETS)

# NOTE: when using this command you might want to change the `test` target to
# only run a subset of the tests you're actively working on.
dev:
	find src/ tests/ Makefile Cargo.toml | entr -d -c $(MAKE) test

clean:
	cargo clean

.PHONY: test test_all check_all_targets $(TARGETS) install_targets dev clean
