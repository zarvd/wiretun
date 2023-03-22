default:
    just --list

# Run unit tests against the current platform
unit-test:
    cargo nextest run

# Format code with rust
fmt:
    cargo fmt

# Lint code with clippy
lint:
    cargo clippy