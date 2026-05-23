# BrightNexus for Linux

Hardware-anchored **BrightLink** bridge and GTK system-tray agent for Ubuntu/Linux. Wire-compatible with the macOS [BrightNexus](https://github.com/Digital-Defiance/BrightNexus) reference.

Repository: https://github.com/Digital-Defiance/BrightNexus-linux

## Features

- EBP/1 + BrightLink on `~/.brightchain/brightnexus/brightnexus.sock`
- `Tpm2BridgeIdentity` (optional `tpm2` feature) or `FileBridgeIdentity` with optional libsecret wrapping
- Linux peer attestation (`SO_PEERCRED`, dpkg, lineage)
- Geo: GeoClue2 (optional) or fixed/test source
- GTK4 / libadwaita tray and settings UI

## Install (PPA)

```bash
sudo add-apt-repository ppa:digitaldefiance/brightnexus
sudo apt update
sudo apt install brightnexus
```

## Rust toolchain (MSRV **1.85**)

Transitive crypto crates (e.g. `base64ct` 1.8.x) require **Rust 1.85+** (edition 2024). The repo pins **`stable`** via [`rust-toolchain.toml`](rust-toolchain.toml).

**Ubuntu 24.04 Noble:** do **not** use the distro `cargo` package (Rust **1.75**). Install [rustup](https://rustup.rs) and use stable:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup default stable
rustc --version   # must be 1.85.0 or newer
```

If compile errors mention `peer_cred` or `E0658` (unstable), the active toolchain is too old — run `rustup update stable` and confirm `rustc --version` is **1.85+** (Noble's `apt install cargo` ships Rust 1.75 and will not work).

Optional: remove `apt` Rust so `which cargo` points at `~/.cargo/bin/cargo`:

```bash
sudo apt remove -y cargo rustc  # if installed
```

Parallels / VM testing: see [`docs/TESTING-PARALLELS.md`](docs/TESTING-PARALLELS.md).

## Build

```bash
cargo build --release -p brightnexus-gtk
```

Headless bridge only (no GTK):

```bash
cargo build --release -p brightnexus-bridge
```

With TPM2 (requires system `libtss2`):

```bash
cargo build --release -p brightnexus-platform --features tpm2
cargo build --release -p brightnexus-gtk --features brightnexus-platform/tpm2
```

## Run

```bash
./target/release/brightnexus-bridge
# or full UI
./target/release/brightnexus
```

Environment:

- `BRIGHTNEXUS_SOCKET` — override Unix socket path
- `BRIGHTNEXUS_REQUIRE_HARDWARE=1` — refuse to start without TPM2-backed bridge identity

## Docs & site

Marketing site (GitHub Pages): [linexus.digitaldefiance.org](https://linexus.digitaldefiance.org) — sources under `docs/`.

Protocol: [BrightLink](https://github.com/Digital-Defiance/BrightChain/blob/main/docs/papers/brightlink.md).

Debian packaging: `debian/`; Launchpad upload notes in `packaging/launchpad/README.md`.

## License

MIT
