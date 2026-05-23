# Testing BrightNexus-linux on Ubuntu in Parallels

Use an Ubuntu VM on macOS (Parallels) to exercise GeoClue, GTK, and the headless bridge without relying on macOS-only tooling.

## Prerequisites on the VM

- **Ubuntu 24.04 LTS** — `arm64` if the host is Apple Silicon, `x86_64` on Intel Macs.
- **Build dependencies:**

```bash
sudo apt update && sudo apt install -y \
  build-essential pkg-config libssl-dev libsecp256k1-dev \
  libgtk-4-dev libadwaita-1-dev libsecret-1-dev \
  geoclue-2.0 geoclue-2-demo \
  git curl
```

- **Rust (rustup stable, MSRV 1.85+):** Noble’s `apt install cargo` ships **Rust 1.75**, which cannot build this workspace (`base64ct` 1.8.x needs edition 2024 / rustc 1.85+). Use rustup only:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup default stable
rustc --version   # expect 1.85.0 or newer
```

If you previously installed `cargo` from apt, remove it so `~/.cargo/bin` is first on `PATH`:

```bash
sudo apt remove -y cargo rustc 2>/dev/null || true
which cargo   # should be $HOME/.cargo/bin/cargo
```

The repo’s [`rust-toolchain.toml`](../rust-toolchain.toml) selects `stable` automatically when rustup is installed.

- **Clone:**

```bash
git clone https://github.com/Digital-Defiance/BrightNexus-linux.git
cd BrightNexus-linux
```

## Build and run

**Headless bridge (no GeoClue required):**

```bash
cargo build --release -p brightnexus-bridge
BRIGHTNEXUS_GEO_SOURCE=fixed ./target/release/brightnexus-bridge
```

**Full UI with GeoClue:**

```bash
cargo build --release -p brightnexus-gtk --features ui,brightnexus-platform/geoclue
./target/release/brightnexus
```

Runtime geo selection (without `BRIGHTNEXUS_GEO_SOURCE`):

1. GeoClue when the `geoclue` feature is enabled and the GeoClue2 D-Bus service is available.
2. Coarse IP fallback (`IpGeoSource`) otherwise.
3. `BRIGHTNEXUS_GEO_SOURCE=fixed` — deterministic San Francisco coordinates for CI and local tests.
4. `BRIGHTNEXUS_GEO_SOURCE=ip` — force IP fallback.
5. `BRIGHTNEXUS_GEO_SOURCE=geoclue` — force GeoClue (requires `geoclue` feature).

## Verify the bridge

- **Socket:** `~/.brightchain/brightnexus/brightnexus.sock`
- **Integration tests:**

```bash
BRIGHTNEXUS_GEO_SOURCE=fixed cargo test -p brightnexus-bridge --test integration
```

- **Optional:** build [libbrightlink](https://github.com/Digital-Defiance/libbrightlink) from a sibling checkout and run its tests against a running bridge.

## GeoClue on the VM

**Location is not a Parallels setting.** Parallels only passes through what the guest OS reports — you configure location inside Ubuntu.

1. **Ubuntu:** Settings → **Privacy** → **Location Services** → **ON**.
2. Install GeoClue (included in the build-deps above): `sudo apt install -y geoclue-2.0 geoclue-2-demo`.
3. Check the daemon:
   - `systemctl --user status geoclue` (if applicable), or
   - `busctl --system introspect org.freedesktop.GeoClue2`
4. Confirm fixes with `geoclue-2-demo`.

If GeoClue is unavailable, use `BRIGHTNEXUS_GEO_SOURCE=fixed` or `=ip` for bridge tests (see [Build and run](#build-and-run)).

## TPM 2.0 (optional)

TPM is a **Parallels hardware device**, not an Ubuntu setting. Availability varies by Parallels version and edition; on some builds the option is under **Security** instead of **Hardware**, or is offered only for Windows guests.

1. **Parallels Desktop** → select the VM → **Configure** / **Settings** → **Hardware** → add or enable a **TPM** chip (TPM 2.0).
2. If no TPM device is listed, use the default **FileBridgeIdentity** (software-backed keys) and **do not** set `BRIGHTNEXUS_REQUIRE_HARDWARE`. TPM testing on a Linux guest may require **Parallels Pro** and an explicitly added TPM device.

Build and run only when a TPM is present in the guest:

```bash
cargo build --release -p brightnexus-bridge --features tpm2
BRIGHTNEXUS_REQUIRE_HARDWARE=1 ./target/release/brightnexus-bridge
```

## Networking

- Parallels **Shared Network** is the default; the bridge Unix socket is local-only — no extra firewall rules.

## Parallels tips

- Install the **Ubuntu ARM64** ISO on Apple Silicon hosts.
- Allocate **4 GB+ RAM** for GTK release builds.
- **Shared folders** (optional): mount the macOS repo at e.g. `/media/psf/Code/BrightNexus-Linux` or sync from `/Volumes/Code/BrightNexus-Linux` on the host.

## CI parity

GitHub Actions runs `cargo test --workspace` with `BRIGHTNEXUS_GEO_SOURCE=fixed` on `ubuntu-24.04`. Match that locally before pushing:

```bash
BRIGHTNEXUS_GEO_SOURCE=fixed cargo test --workspace
```

### VM CI script

For a full Noble VM setup (apt deps, rustup MSRV check, workspace tests, optional release builds), use [`scripts/ci-vm.sh`](../scripts/ci-vm.sh):

```bash
curl -fsSL https://raw.githubusercontent.com/Digital-Defiance/BrightNexus-linux/main/scripts/ci-vm.sh -o ci-vm.sh
chmod +x ci-vm.sh
./ci-vm.sh              # tests only
./ci-vm.sh --release    # tests + release bridge and GTK UI
```

From an existing clone, run `./scripts/ci-vm.sh` directly. Set `REPO_DIR` to use a checkout path other than `~/BrightNexus-linux`.
