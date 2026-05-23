use std::env;
use std::sync::RwLock;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerAttestationMode {
    LogOnly,
    Enforce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    pub peer_attestation_mode: PeerAttestationMode,
    /// Default 1 hour, max 8 hours per spec clamp range.
    pub credential_ttl_ceiling_seconds: i64,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            peer_attestation_mode: PeerAttestationMode::LogOnly,
            credential_ttl_ceiling_seconds: 3600,
        }
    }
}

static POLICY: RwLock<Policy> = RwLock::new(Policy {
    peer_attestation_mode: PeerAttestationMode::LogOnly,
    credential_ttl_ceiling_seconds: 3600,
});

pub fn policy() -> Policy {
    *POLICY.read().unwrap()
}

pub fn set_peer_attestation_mode(mode: PeerAttestationMode) {
    POLICY.write().unwrap().peer_attestation_mode = mode;
}

pub fn set_ttl_ceiling(seconds: i64) {
    let clamped = seconds.clamp(60, 8 * 3600);
    POLICY.write().unwrap().credential_ttl_ceiling_seconds = clamped;
}

pub fn require_hardware() -> bool {
    env::var("BRIGHTNEXUS_REQUIRE_HARDWARE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}
