default:
    just --list

# Build the project
build:
    cargo build

# Run unit tests against the current platform
unit-test:
    cargo nextest run

# Run integration tests against the current platform (Require sudo)
integration-test:
    #!/usr/bin/env bash
    pushd integration-tests/wiretun-to-wiretun
    sudo ./run-test.sh
    popd

# Format code with rust
fmt:
    cargo fmt

# Lint code with clippy
lint:
    cargo clippy