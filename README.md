# WireTun

[<img alt="github" height="20" src="https://img.shields.io/badge/github-lodrem/wiretun-8da0cb?style=for-the-badge&labelColor=555555&logo=github">](https://github.com/lodrem/wiretun)
[<img alt="crates.io" height="20" src="https://img.shields.io/crates/v/wiretun.svg?style=for-the-badge&color=fc8d62&logo=rust">](https://crates.io/crates/wiretun)
[<img alt="docs.rs" height="20" src="https://img.shields.io/docsrs/wiretun?style=for-the-badge">](https://docs.rs/wiretun)
[<img alt="build status" height="20" src="https://img.shields.io/github/actions/workflow/status/lodrem/wiretun/ci.yml?branch=master&style=for-the-badge">](https://github.com/lodrem/wiretun/actions?query%3Amaster)
[<img alt="dependency status" height="20" src="https://deps.rs/repo/github/lodrem/wiretun/status.svg?style=for-the-badge&t=0">](https://deps.rs/repo/github/lodrem/wiretun)

This library provides a cross-platform, asynchronous (with [Tokio](https://tokio.rs/)) [WireGuard](https://www.wireguard.com/) implementation.

**WARNING**: This library is still in early development and is not ready for production use.

```toml
[dependencies]
wiretun = { version = "*", features = ["uapi"] }
```

## Example

```rust
use wiretun::{Cidr, Device, DeviceConfig, PeerConfig, uapi};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
   let cfg = DeviceConfig::default()
       .listen_port(40001);
   let device = Device::native("utun88", cfg).await?;
   uapi::bind_and_handle(device.control()).await?;
   Ok(())
}
```

More examples can be found in the [examples](examples) directory.

## Minimum supported Rust version (MSRV)

1.66.1

## License

This project is licensed under the [Apache 2.0 license](LICENSE).
