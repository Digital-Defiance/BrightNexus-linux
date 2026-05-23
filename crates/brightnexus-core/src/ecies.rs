//! DD-ECIES Basic mode (cipher suite 0x21) — matches libbrightlink / macOS.

use rand::RngCore;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use zeroize::Zeroizing;

pub const DD_ECIES_VERSION: u8 = 0x01;
pub const DD_ECIES_CIPHER_SUITE: u8 = 0x01;
pub const DD_ECIES_TYPE_BASIC: u8 = 0x21;
pub const DD_ECIES_HKDF_INFO: &[u8] = b"ecies-v2-key-derivation";

pub fn ecies_encrypt(recipient_pub65: &[u8; 65], plaintext: &[u8]) -> crate::Result<Vec<u8>> {
    let secp = Secp256k1::new();
    let mut rng = rand::thread_rng();
    let eph_secret = SecretKey::new(&mut rng);
    let eph_pub = PublicKey::from_secret_key(&secp, &eph_secret);
    let mut eph_compressed = [0u8; 33];
    eph_compressed.copy_from_slice(&eph_pub.serialize());

    let recipient = PublicKey::from_slice(recipient_pub65)
        .map_err(|e| crate::BridgeError::Crypto(e.to_string()))?;
    let shared = secp256k1::ecdh::shared_secret_point(&recipient, &eph_secret);
    let shared_x = &shared[1..33];

    let aes_key = crate::crypto::hkdf_sha256(shared_x, b"", DD_ECIES_HKDF_INFO, 32)?;
    let key: [u8; 32] = aes_key.try_into().unwrap();

    let mut iv = [0u8; 12];
    rng.fill_bytes(&mut iv);

    let mut aad = vec![DD_ECIES_VERSION, DD_ECIES_CIPHER_SUITE, DD_ECIES_TYPE_BASIC];
    aad.extend_from_slice(&eph_compressed);

    let (ct, tag) = crate::crypto::aes_gcm_encrypt(&key, &iv, &aad, plaintext)?;

    let mut env = Vec::with_capacity(64 + ct.len());
    env.push(DD_ECIES_VERSION);
    env.push(DD_ECIES_CIPHER_SUITE);
    env.push(DD_ECIES_TYPE_BASIC);
    env.extend_from_slice(&eph_compressed);
    env.extend_from_slice(&iv);
    env.extend_from_slice(&tag);
    env.extend_from_slice(&ct);
    Ok(env)
}

pub fn ecies_decrypt(recipient_priv32: &[u8; 32], envelope: &[u8]) -> crate::Result<Vec<u8>> {
    if envelope.len() < 64 {
        return Err(crate::BridgeError::Crypto("envelope too short".into()));
    }
    if envelope[0] != DD_ECIES_VERSION
        || envelope[1] != DD_ECIES_CIPHER_SUITE
        || envelope[2] != DD_ECIES_TYPE_BASIC
    {
        return Err(crate::BridgeError::Crypto("invalid envelope header".into()));
    }
    if envelope[3] != 0x02 && envelope[3] != 0x03 {
        return Err(crate::BridgeError::Crypto("invalid ephemeral key".into()));
    }
    let eph_pub = &envelope[3..36];
    let iv = &envelope[36..48];
    let tag = &envelope[48..64];
    let ct = &envelope[64..];

    let priv_key = SecretKey::from_slice(recipient_priv32)
        .map_err(|e| crate::BridgeError::Crypto(e.to_string()))?;
    let peer = PublicKey::from_slice(eph_pub)
        .map_err(|e| crate::BridgeError::Crypto(e.to_string()))?;
    let shared = secp256k1::ecdh::shared_secret_point(&peer, &priv_key);
    let shared_x = &shared[1..33];

    let aes_key = crate::crypto::hkdf_sha256(shared_x, b"", DD_ECIES_HKDF_INFO, 32)?;
    let key: [u8; 32] = aes_key.try_into().unwrap();

    let mut aad = vec![DD_ECIES_VERSION, DD_ECIES_CIPHER_SUITE, DD_ECIES_TYPE_BASIC];
    aad.extend_from_slice(eph_pub);

    crate::crypto::aes_gcm_decrypt(&key, iv, &aad, ct, tag)
}

pub fn load_or_create_ecies_key(path: &std::path::Path) -> crate::Result<Zeroizing<[u8; 32]>> {
    use std::io::Write;
use std::fs;
    use std::os::unix::fs::OpenOptionsExt;
    if path.exists() {
        let data = fs::read(path)?;
        if data.len() != 32 {
            return Err(crate::BridgeError::Crypto("invalid ecies key file".into()));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&data);
        return Ok(Zeroizing::new(key));
    }
    let secp = Secp256k1::new();
    let mut rng = rand::thread_rng();
    let (secret, _) = secp.generate_keypair(&mut rng);
    let bytes = secret.secret_bytes();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .mode(0o600)
        .open(path)?
        .write_all(&bytes)?;
    Ok(Zeroizing::new(bytes))
}

pub fn ecies_public_key(priv32: &[u8; 32]) -> crate::Result<[u8; 65]> {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(priv32).map_err(|e| crate::BridgeError::Crypto(e.to_string()))?;
    let pk = PublicKey::from_secret_key(&secp, &sk);
    Ok(pk.serialize_uncompressed())
}
