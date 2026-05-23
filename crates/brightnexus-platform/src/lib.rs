//! Linux platform pluggables.

pub mod attestation;
pub mod factory;
pub mod file_identity;
pub mod geo_source;

#[cfg(feature = "tpm2")]
pub mod tpm2;

#[cfg(feature = "geoclue")]
pub mod geoclue;

pub use factory::{select_bridge_identity, select_geo_source};
pub use geo_source::IpGeoSource;
