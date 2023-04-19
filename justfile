default:
    just --list

# Build the project
build:
    cargo build

# Format code with rust
fmt:
    cargo fmt

# Lint code with clippy
lint:
    cargo fmt --all -- --check
    cargo clippy --all-targets --all-features

# Run unit tests against the current platform
unit-test:
    cargo nextest run
    cargo test --doc

# Run integration tests against the current platform (Require sudo)
integration-test: integration-test-native-tun integration-test-wiretun-to-wiretun integration-test-wireguard-to-wiretun

# Run integration test scenario: native TUN
integration-test-native-tun:
    #!/usr/bin/env bash
    set -e
    pushd integration-tests/native-tun
    ./pre-test.sh
    sudo ./run-test.sh
    popd

# Run integration test scenario: WireTun to WireTun
integration-test-wiretun-to-wiretun:
    #!/usr/bin/env bash
    set -e
    pushd integration-tests/wiretun-to-wiretun
    ./pre-test.sh
    sudo ./run-test.sh
    popd

# Run integration test scenario: WireGuard to WireTun
integration-test-wireguard-to-wiretun:
    #!/usr/bin/env bash
    set -e
    pushd integration-tests/wireguard-to-wiretun
    ./pre-test.sh
    sudo ./run-test.sh
    popd

