//! Known-answer tests aligned with libbrightlink constants (RFC §13).

use brightnexus_core::ecies::DD_ECIES_HKDF_INFO;
use brightnexus_core::session::{
    build_deliver_aad, build_transcript, derive_session_key, HKDF_INFO, TRANSCRIPT_HEADER,
};

const CLIENT_NONCE: [u8; 16] = [0x01; 16];
const CLIENT_PUB: [u8; 65] = [0x04; 65];
const CLIENT_SHARE: [u8; 32] = [0x02; 32];
const SESSION_ID: [u8; 16] = [0x03; 16];
const BRIDGE_SHARE: [u8; 32] = [0x04; 32];
const ISSUED_AT_BD: f64 = 9638.0;
const BRIDGE_ISSUED_AT_UNIX: i64 = 1_700_000_000;
const TTL_SECONDS: i64 = 3600;

#[test]
fn hkdf_session_key_matches_libbrightlink_vector() {
    let key = derive_session_key(&CLIENT_SHARE, &BRIDGE_SHARE, &CLIENT_NONCE, &SESSION_ID)
        .expect("derive_session_key");
    assert_eq!(
        hex::encode(key),
        include_str!("../../../tests/vectors/session-hkdf-v1.hex").trim()
    );
    assert_eq!(HKDF_INFO, b"brightlink-session-key-v1");
}

#[test]
fn transcript_header_and_length_match_spec() {
    let transcript = build_transcript(
        &CLIENT_NONCE,
        &CLIENT_PUB,
        &CLIENT_SHARE,
        &SESSION_ID,
        &BRIDGE_SHARE,
        ISSUED_AT_BD,
        BRIDGE_ISSUED_AT_UNIX,
        TTL_SECONDS,
    )
    .expect("build_transcript");
    assert_eq!(transcript.len(), 238);
    assert_eq!(&transcript[..25], TRANSCRIPT_HEADER);
    assert_eq!(
        hex::encode(&transcript),
        include_str!("../../../tests/vectors/transcript-v1.hex").trim()
    );
}

#[test]
fn dd_ecies_hkdf_info_matches_libbrightlink() {
    assert_eq!(DD_ECIES_HKDF_INFO, b"ecies-v2-key-derivation");
    let ikm = hex::decode("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
        .unwrap();
    let key = brightnexus_core::crypto::hkdf_sha256(&ikm, b"", DD_ECIES_HKDF_INFO, 32)
        .expect("hkdf");
    assert_eq!(
        hex::encode(key),
        include_str!("../../../tests/vectors/dd-ecies-hkdf-v1.hex").trim()
    );
}

#[test]
fn dd_ecies_roundtrip_matches_basic_mode() {
    use brightnexus_core::ecies::{ecies_decrypt, ecies_encrypt, ecies_public_key};
    let priv_key = [0x11u8; 32];
    let pub_key = ecies_public_key(&priv_key).expect("pub");
    let plaintext = br#"{"v":1,"clientPub":"test"}"#;
    let envelope = ecies_encrypt(&pub_key, plaintext).expect("encrypt");
    assert_eq!(envelope[0], 0x01);
    assert_eq!(envelope[1], 0x01);
    assert_eq!(envelope[2], 0x21);
    let decrypted = ecies_decrypt(&priv_key, &envelope).expect("decrypt");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn deliver_aad_layout_matches_spec() {
    let aad = build_deliver_aad(0x01, 42, "credential", "ssh");
    assert_eq!(&aad[0..4], &[1, 0, 0, 0]);
    assert_eq!(aad[4], 0x01);
    assert_eq!(&aad[5..9], &[8, 0, 0, 0]);
    assert_eq!(&aad[9..17], &42u64.to_be_bytes());
    let type_len = u32::from_le_bytes(aad[17..21].try_into().unwrap()) as usize;
    assert_eq!(&aad[21..21 + type_len], b"credential");
    let ctx_off = 21 + type_len;
    let ctx_len = u32::from_le_bytes(aad[ctx_off..ctx_off + 4].try_into().unwrap()) as usize;
    assert_eq!(&aad[ctx_off + 4..ctx_off + 4 + ctx_len], b"ssh");
}
