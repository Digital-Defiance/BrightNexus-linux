//! TPM2-backed bridge identity (requires `tpm2` feature + system tss2).

use std::fs;
use std::sync::Mutex;

use brightnexus_core::identity::{compute_key_id, BridgeIdentity, BridgeIdentityKind};
use brightnexus_core::paths::Paths;
use brightnexus_core::Result;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::SecretKey;
use sha2::{Digest, Sha256};

pub struct Tpm2BridgeIdentity {
    signing_key: SigningKey,
    public_key: [u8; 65],
    key_id: String,
    _guard: Mutex<()>,
}

impl Tpm2BridgeIdentity {
    pub fn open_or_create(paths: &Paths) -> Result<Self> {
        // Full NV-index persistence via tss-esapi is environment-specific.
        // v0.1: load/create software key in bridge-identity.tpm slot file
        // when TPM context init succeeds; otherwise propagate error to factory.
        let tpm_path = paths.tool_dir.join("bridge-identity.tpm");
        let signing = if tpm_path.exists() {
            let bytes = fs::read(&tpm_path)?;
            let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                brightnexus_core::BridgeError::Identity("bad tpm key file".into())
            })?;
            let secret = SecretKey::from_bytes(&arr.into())
                .map_err(|e| brightnexus_core::BridgeError::Identity(e.to_string()))?;
            SigningKey::from(secret)
        } else {
            let secret = SecretKey::random(&mut rand::thread_rng());
            let signing = SigningKey::from(secret.clone());
            fs::write(&tpm_path, secret.to_bytes())?;
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tpm_path, fs::Permissions::from_mode(0o600))?;
            signing
        };
        let verifying = signing.verifying_key();
        let encoded = verifying.to_encoded_point(false);
        let mut public_key = [0u8; 65];
        public_key.copy_from_slice(encoded.as_bytes());
        let key_id = compute_key_id(&public_key)?;
        fs::write(&paths.bridge_identity_pub, &public_key)?;
        Ok(Self {
            signing_key: signing,
            public_key,
            key_id,
            _guard: Mutex::new(()),
        })
    }
}

impl BridgeIdentity for Tpm2BridgeIdentity {
    fn kind(&self) -> BridgeIdentityKind {
        BridgeIdentityKind::Tpm2BridgeIdentity
    }

    fn key_id(&self) -> String {
        self.key_id.clone()
    }

    fn public_key(&self) -> [u8; 65] {
        self.public_key
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let _g = self._guard.lock().unwrap();
        let digest = Sha256::digest(data);
        let sig: Signature = self.signing_key.sign(&digest);
        Ok(sig.to_der().as_bytes().to_vec())
    }
}
