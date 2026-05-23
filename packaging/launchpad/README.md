# Launchpad / PPA upload instructions for brightnexus

## Prerequisites

- `debuild`, `dput`, `devscripts`
- Rust toolchain matching `debian/control` (`rustc >= 1.74`)
- Launchpad PPA remote configured as `brightnexus` (or your PPA name)

## Build source package

From the repository root:

```bash
export DEBFULLNAME="Jessica Mulein"
export DEBEMAIL="jessica@digitaldefiance.org"
dch --newversion 0.1.0-1 "Release for PPA"
debuild -S -sa
```

This produces `../brightnexus_0.1.0-1_source.changes` in the parent directory.

## Upload to Launchpad

```bash
dput brightnexus ../brightnexus_0.1.0-1_source.changes
```

If your remote uses the default Launchpad name:

```bash
dput ppa:digitaldefiance/brightnexus ../brightnexus_0.1.0-1_source.changes
```

## PPA consumer install line

```bash
sudo add-apt-repository ppa:digitaldefiance/brightnexus
sudo apt update
sudo apt install brightnexus
```

## Notes

- Package ships `brightnexus` (GTK tray) and `brightnexus-bridge` (headless).
- TPM2 builds require `libtss2-dev` at compile time; enable with
  `cargo build --features brightnexus-platform/tpm2` before adjusting `debian/rules`
  if you publish a hardware-enabled PPA variant.
- `debian/postinst` creates `~/.brightchain/brightnexus/` with mode `0700` for the
  installing user.
