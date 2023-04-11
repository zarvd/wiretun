default:
    just --list

# Build the project
build:
    cargo build

# Run unit tests against the current platform
unit-test:
    cargo nextest run
    cargo test --doc

# Run integration tests against the current platform (Require sudo)
integration-test:
    #!/usr/bin/env bash
    set -e
    pushd integration-tests/wiretun-to-wiretun
    ./pre-test.sh
    sudo ./run-test.sh
    popd

    pushd integration-tests/native-tun
    ./pre-test.sh
    sudo ./run-test.sh
    popd

# Format code with rust
fmt:
    cargo fmt

# Lint code with clippy
lint:
    cargo clippy --all-targets --all-features
