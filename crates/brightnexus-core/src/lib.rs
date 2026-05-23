//! BrightNexus core — protocol, crypto, credentials, geo.

pub mod bridge;
pub mod credentials;
pub mod crypto;
pub mod ecies;
pub mod error;
pub mod geo;
pub mod handler;
pub mod identity;
pub mod paths;
pub mod policy;
pub mod session;
pub mod socket;

pub use bridge::Bridge;
pub use error::{BridgeError, Result};
pub use identity::{BridgeIdentity, BridgeIdentityKind};
pub use paths::Paths;
