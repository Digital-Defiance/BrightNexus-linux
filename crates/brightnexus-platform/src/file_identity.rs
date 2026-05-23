use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Mutex;

use brightnexus_core::identity::{compute_key_id, BridgeIdentity, BridgeIdentityKind};
use brightnexus_core::paths::Paths;
use brightnexus_core::Result;
use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::SecretKey;
use rand::rngs::OsRng;
use zeroize::Zeroizing;

const SERVICE: &str = "BrightNexus";
const COLLECTION_PREFIX: &str = "bridge-identity";

pub struct FileBridgeIdentity {
    signing_key: SigningKey,
    public_key: [u8; 65],
    key_id: String,
    secret_guard: Mutex<()>,
}

impl FileBridgeIdentity {
    pub fn open_or_create(paths: &Paths) -> Result<Self> {
        if let Ok(raw) = try_load_secret_file(&paths.bridge_identity_key) {
            return Self::from_bytes(raw, paths);
        }
        if let Ok(raw) = try_load_secret_keyring(paths) {
            return Self::from_bytes(raw, paths);
        }
        let secret = SecretKey::random(&mut OsRng);
        let signing = SigningKey::from(secret.clone());
        let bytes = Zeroizing::new(secret.to_bytes().to_vec());
        save_secret(paths, &bytes)?;
        Self::from_signing_key(signing, paths)
    }

    fn from_bytes(bytes: Zeroizing<Vec<u8>>, paths: &Paths) -> Result<Self> {
        let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
            brightnexus_core::BridgeError::Identity("invalid key length".into())
        })?;
        let secret = SecretKey::from_bytes(&arr.into())
            .map_err(|e| brightnexus_core::BridgeError::Identity(e.to_string()))?;
        let signing = SigningKey::from(secret);
        Self::from_signing_key(signing, paths)
    }

    fn from_signing_key(signing: SigningKey, paths: &Paths) -> Result<Self> {
        let verifying: VerifyingKey = signing.verifying_key().clone();
        let encoded = verifying.to_encoded_point(false);
        let mut public_key = [0u8; 65];
        public_key.copy_from_slice(encoded.as_bytes());
        let key_id = compute_key_id(&public_key)?;
        if let Some(parent) = paths.bridge_identity_pub.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&paths.bridge_identity_pub, &public_key)?;
        let _ = fs::set_permissions(&paths.bridge_identity_pub, fs::Permissions::from_mode(0o600));
        Ok(Self {
            signing_key: signing,
            public_key,
            key_id,
            secret_guard: Mutex::new(()),
        })
    }
}

impl BridgeIdentity for FileBridgeIdentity {
    fn kind(&self) -> BridgeIdentityKind {
        BridgeIdentityKind::FileBridgeIdentity
    }

    fn key_id(&self) -> String {
        self.key_id.clone()
    }

    fn public_key(&self) -> [u8; 65] {
        self.public_key
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        use sha2::{Digest, Sha256};
        let _g = self.secret_guard.lock().unwrap();
        let digest = Sha256::digest(data);
        let sig: Signature = self.signing_key.sign(&digest);
        Ok(sig.to_der().as_bytes().to_vec())
    }
}

fn keyring_collection(paths: &Paths) -> String {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(paths.bridge_identity_key.to_string_lossy().as_bytes());
    format!("{COLLECTION_PREFIX}-{}", hex::encode(&d[..8]))
}

fn try_load_secret_keyring(paths: &Paths) -> Result<Zeroizing<Vec<u8>>> {
    use base64::Engine;
    let collection = keyring_collection(paths);
    let entry = keyring::Entry::new(SERVICE, &collection).map_err(|e| {
        brightnexus_core::BridgeError::Identity(e.to_string())
    })?;
    let encoded = entry.get_password().map_err(|_| {
        brightnexus_core::BridgeError::msg("missing")
    })?;
    let data = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .map_err(|e| brightnexus_core::BridgeError::Identity(e.to_string()))?;
    if data.len() != 32 {
        return Err(brightnexus_core::BridgeError::Identity(
            "invalid bridge-identity.key".into(),
        ));
    }
    Ok(Zeroizing::new(data))
}

fn try_load_secret_file(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    if !path.exists() {
        return Err(brightnexus_core::BridgeError::msg("missing"));
    }
    let data = fs::read(path)?;
    if data.len() == 32 {
        return Ok(Zeroizing::new(data));
    }
    Err(brightnexus_core::BridgeError::Identity(
        "invalid bridge-identity.key".into(),
    ))
}

fn save_secret(paths: &Paths, bytes: &Zeroizing<Vec<u8>>) -> Result<()> {
    use base64::Engine;
    fs::write(&paths.bridge_identity_key, bytes.as_slice())?;
    fs::set_permissions(
        &paths.bridge_identity_key,
        fs::Permissions::from_mode(0o600),
    )?;
    let collection = keyring_collection(paths);
    if let Ok(entry) = keyring::Entry::new(SERVICE, &collection) {
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes.as_slice());
        if entry.set_password(&encoded).is_ok() {
            tracing::info!("mirrored bridge identity to libsecret keyring");
        }
    }
    Ok(())
}
