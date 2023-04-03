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
    sudo ./integration-tests/wiretun-to-wiretun/run-tests.sh

# Format code with rust
fmt:
    cargo fmt

# Lint code with clippy
lint:
    cargo clippy