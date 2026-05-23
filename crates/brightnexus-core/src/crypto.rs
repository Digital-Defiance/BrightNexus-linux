use hkdf::Hkdf;
use sha2::Sha256;

pub fn hkdf_sha256(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    out_len: usize,
) -> crate::Result<Vec<u8>> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; out_len];
    hk.expand(info, &mut okm)
        .map_err(|e| crate::BridgeError::Crypto(e.to_string()))?;
    Ok(okm)
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    Sha256::digest(data).into()
}

pub fn aes_gcm_decrypt(
    key: &[u8; 32],
    iv: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
) -> crate::Result<Vec<u8>> {
    use aes_gcm::aead::{AeadInPlace, KeyInit};
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use aes_gcm::Tag;
    if iv.len() != 12 || tag.len() != 16 {
        return Err(crate::BridgeError::Crypto("invalid iv/tag length".into()));
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(iv);
    let mut buf = ciphertext.to_vec();
    let tag_arr = Tag::from_slice(tag);
    cipher
        .decrypt_in_place_detached(nonce, aad, &mut buf, tag_arr)
        .map_err(|e| crate::BridgeError::Crypto(e.to_string()))?;
    Ok(buf)
}

pub fn aes_gcm_encrypt(
    key: &[u8; 32],
    iv: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> crate::Result<(Vec<u8>, [u8; 16])> {
    use aes_gcm::aead::{AeadInPlace, KeyInit};
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    if iv.len() != 12 {
        return Err(crate::BridgeError::Crypto("invalid iv length".into()));
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(iv);
    let mut buf = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(nonce, aad, &mut buf)
        .map_err(|e| crate::BridgeError::Crypto(e.to_string()))?;
    Ok((buf, tag.into()))
}
