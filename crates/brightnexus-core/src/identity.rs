use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub enum BridgeIdentityKind {
    SepBridgeIdentity,
    Tpm2BridgeIdentity,
    FileBridgeIdentity,
}

impl BridgeIdentityKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::SepBridgeIdentity => "SepBridgeIdentity",
            Self::Tpm2BridgeIdentity => "Tpm2BridgeIdentity",
            Self::FileBridgeIdentity => "FileBridgeIdentity",
        }
    }

    pub fn is_hardware_backed(&self) -> bool {
        matches!(self, Self::SepBridgeIdentity | Self::Tpm2BridgeIdentity)
    }
}

/// RFC §6.1 signing identity for transcript + ACL signatures.
pub trait BridgeIdentity: Send + Sync {
    fn kind(&self) -> BridgeIdentityKind;
    fn key_id(&self) -> String;
    fn public_key(&self) -> [u8; 65];
    fn sign(&self, data: &[u8]) -> crate::Result<Vec<u8>>;
}

pub fn compute_key_id(public_key65: &[u8; 65]) -> crate::Result<String> {
    use base64::Engine;
    use sha2::{Digest, Sha256};
    if public_key65[0] != 0x04 {
        return Err(crate::BridgeError::Identity(
            "public key must be uncompressed P-256".into(),
        ));
    }
    let digest = Sha256::digest(public_key65);
    let prefix = &digest[..16];
    let b64 = base64::engine::general_purpose::STANDARD.encode(prefix);
    let b64url = b64.replace('+', "-").replace('/', "_").trim_end_matches('=').to_string();
    Ok(format!("p256:{b64url}"))
}
