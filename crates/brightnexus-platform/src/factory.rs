use std::fs;
#[cfg(feature = "tpm2")]
use std::path::Path;
use std::sync::Arc;

use brightnexus_core::geo::{FixedGeoSource, GeoSource};
use brightnexus_core::identity::{BridgeIdentity, BridgeIdentityKind};
use brightnexus_core::paths::Paths;
use brightnexus_core::policy;
use brightnexus_core::Result;

use crate::file_identity::FileBridgeIdentity;
use crate::geo_source::IpGeoSource;

#[cfg(feature = "geoclue")]
use crate::geoclue::GeoClueGeoSource;

#[cfg(feature = "tpm2")]
use crate::tpm2::Tpm2BridgeIdentity;

pub fn select_bridge_identity(paths: &Paths) -> Result<Arc<dyn BridgeIdentity>> {
    #[cfg(feature = "tpm2")]
    if tpm_available() {
        match Tpm2BridgeIdentity::open_or_create(paths) {
            Ok(id) => {
                tracing::info!("selected Tpm2BridgeIdentity");
                return Ok(Arc::new(id));
            }
            Err(e) => {
                tracing::warn!("TPM2 identity unavailable: {e}");
                if policy::require_hardware() {
                    return Err(brightnexus_core::BridgeError::Identity(
                        "BRIGHTNEXUS_REQUIRE_HARDWARE=1 but TPM2 unavailable".into(),
                    ));
                }
            }
        }
    } else if policy::require_hardware() {
        return Err(brightnexus_core::BridgeError::Identity(
            "BRIGHTNEXUS_REQUIRE_HARDWARE=1 but no TPM device found".into(),
        ));
    }

  #[cfg(not(feature = "tpm2"))]
    if policy::require_hardware() {
        return Err(brightnexus_core::BridgeError::Identity(
            "BRIGHTNEXUS_REQUIRE_HARDWARE=1 but build lacks tpm2 feature".into(),
        ));
    }

    tracing::info!("selected FileBridgeIdentity (software-backed fallback)");
    Ok(Arc::new(FileBridgeIdentity::open_or_create(paths)?))
}

#[cfg(feature = "tpm2")]
fn tpm_available() -> bool {
    Path::new("/dev/tpmrm0").exists() || Path::new("/dev/tpm0").exists()
}

pub fn write_identity_kind(paths: &Paths, kind: BridgeIdentityKind) -> Result<()> {
    fs::write(&paths.bridge_identity_kind, kind.as_str())?;
    Ok(())
}

/// Select runtime geo source: GeoClue when available, else coarse IP fallback.
/// Tests and CI set `BRIGHTNEXUS_GEO_SOURCE=fixed` for deterministic coordinates.
pub fn select_geo_source() -> Arc<dyn GeoSource> {
    if let Ok(mode) = std::env::var("BRIGHTNEXUS_GEO_SOURCE") {
        match mode.as_str() {
            "fixed" => {
                tracing::info!("geo: FixedGeoSource (BRIGHTNEXUS_GEO_SOURCE=fixed)");
                return Arc::new(FixedGeoSource::san_francisco());
            }
            "ip" => {
                tracing::info!("geo: IpGeoSource (BRIGHTNEXUS_GEO_SOURCE=ip)");
                return Arc::new(IpGeoSource);
            }
            #[cfg(feature = "geoclue")]
            "geoclue" => {
                tracing::info!("geo: GeoClueGeoSource (BRIGHTNEXUS_GEO_SOURCE=geoclue)");
                return Arc::new(GeoClueGeoSource::new());
            }
            other => tracing::warn!("geo: unknown BRIGHTNEXUS_GEO_SOURCE={other:?}, using auto"),
        }
    }

    #[cfg(feature = "geoclue")]
    if geoclue_likely_available() {
        tracing::info!("geo: GeoClueGeoSource (GeoClue2 D-Bus available)");
        return Arc::new(GeoClueGeoSource::new());
    }

    tracing::info!("geo: IpGeoSource (GeoClue unavailable or geoclue feature disabled)");
    Arc::new(IpGeoSource)
}

#[cfg(feature = "geoclue")]
fn geoclue_likely_available() -> bool {
    std::path::Path::new("/usr/share/dbus-1/system-services/org.freedesktop.GeoClue2.service").exists()
        || which_geoclue_present()
}

#[cfg(feature = "geoclue")]
fn which_geoclue_present() -> bool {
    std::process::Command::new("dbus-send")
        .args([
            "--system",
            "--print-reply",
            "--dest=org.freedesktop.DBus",
            "/org/freedesktop/DBus",
            "org.freedesktop.DBus.NameHasOwner",
            "string:org.freedesktop.GeoClue2",
        ])
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout).contains("boolean true")
        })
        .unwrap_or(false)
}
