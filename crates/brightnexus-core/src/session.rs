use zeroize::Zeroize;

pub const HKDF_INFO: &[u8] = b"brightlink-session-key-v1";
pub const TRANSCRIPT_HEADER: &[u8] = b"BrightLink v1 transcript\0";
pub const TRANSCRIPT_TOTAL_LEN: usize = 238;
pub const CLIENT_NONCE_LEN: usize = 16;
pub const SESSION_ID_LEN: usize = 16;
pub const SHARE_LEN: usize = 32;
pub const SESSION_KEY_LEN: usize = 32;
pub const MAX_TTL_SECONDS: i64 = 8 * 3600;
pub const REPLAY_WINDOW: u64 = 1000;
pub const GCM_IV_LEN: usize = 12;
pub const GCM_TAG_LEN: usize = 16;

#[derive(Debug, Clone)]
pub struct RegisterPlaintext {
    pub v: i32,
    pub client_pub: [u8; 65],
    pub client_share: [u8; 32],
    pub issued_at_bd: f64,
    pub ttl_seconds: i64,
    pub agent_name: String,
    pub agent_version: String,
    pub agent_platform: String,
}

#[derive(Debug, Clone)]
pub struct SessionRecord {
    pub session_id: [u8; SESSION_ID_LEN],
    pub session_key: [u8; SESSION_KEY_LEN],
    pub bridge_issued_at_unix: i64,
    pub ttl_seconds: i64,
    pub agent_name: String,
    pub agent_version: String,
    pub agent_platform: String,
    pub outbound_counter: u64,
    pub last_inbound_counter: u64,
}

impl SessionRecord {
    pub fn expires_at_unix(&self) -> i64 {
        self.bridge_issued_at_unix + self.ttl_seconds
    }

    pub fn wipe(&mut self) {
        self.session_key.zeroize();
    }
}

pub fn derive_session_key(
    client_share: &[u8; SHARE_LEN],
    bridge_share: &[u8; SHARE_LEN],
    client_nonce: &[u8; CLIENT_NONCE_LEN],
    session_id: &[u8; SESSION_ID_LEN],
) -> crate::Result<[u8; SESSION_KEY_LEN]> {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(client_share);
    ikm[32..].copy_from_slice(bridge_share);
    let mut salt = [0u8; 32];
    salt[..16].copy_from_slice(client_nonce);
    salt[16..].copy_from_slice(session_id);
    crate::crypto::hkdf_sha256(&ikm, &salt, HKDF_INFO, SESSION_KEY_LEN)
        .map(|v| v.try_into().expect("hkdf len"))
}

pub fn build_transcript(
    client_nonce: &[u8; CLIENT_NONCE_LEN],
    client_pub: &[u8; 65],
    client_share: &[u8; SHARE_LEN],
    session_id: &[u8; SESSION_ID_LEN],
    bridge_share: &[u8; SHARE_LEN],
    issued_at_bd: f64,
    bridge_issued_at_unix: i64,
    ttl_seconds: i64,
) -> crate::Result<Vec<u8>> {
    let issued_at_unix = (issued_at_bd * 86400.0).round() as u64;
    let mut t = Vec::with_capacity(TRANSCRIPT_TOTAL_LEN);
    t.extend_from_slice(TRANSCRIPT_HEADER);
    append_length_prefixed(&mut t, client_nonce);
    append_length_prefixed(&mut t, client_pub);
    append_length_prefixed(&mut t, client_share);
    append_length_prefixed(&mut t, session_id);
    append_length_prefixed(&mut t, bridge_share);
    append_le32(&mut t, 8);
    append_u64_be(&mut t, issued_at_unix);
    append_le32(&mut t, 8);
    append_u64_be(&mut t, bridge_issued_at_unix as u64);
    append_le32(&mut t, 4);
    append_u32_be(&mut t, ttl_seconds as u32);
    if t.len() != TRANSCRIPT_TOTAL_LEN {
        return Err(crate::BridgeError::msg(format!(
            "transcript length {} != {}",
            t.len(),
            TRANSCRIPT_TOTAL_LEN
        )));
    }
    Ok(t)
}

pub fn parse_register_plaintext(bytes: &[u8]) -> crate::Result<RegisterPlaintext> {
    let v: serde_json::Value = serde_json::from_slice(bytes)?;
    let version = v.get("v").and_then(|x| x.as_i64()).ok_or_else(|| {
        crate::BridgeError::msg("Invalid envelope plaintext")
    })?;
    if version != 1 {
        return Err(crate::BridgeError::msg("Invalid envelope plaintext"));
    }
    let client_pub = decode_b64_fixed::<65>(v.get("clientPub"), 0x04)?;
    let client_share = decode_b64_fixed::<32>(v.get("clientShare"), 0)?;
    let issued_at_bd = v
        .get("issuedAtBd")
        .and_then(|x| x.as_f64())
        .ok_or_else(|| crate::BridgeError::msg("Invalid envelope plaintext"))?;
    let ttl_seconds = v
        .get("ttlSeconds")
        .and_then(|x| x.as_i64())
        .ok_or_else(|| crate::BridgeError::msg("Invalid envelope plaintext"))?;
    let mut agent_name = "unknown".to_string();
    let mut agent_version = "unknown".to_string();
    let mut agent_platform = "unknown".to_string();
    if let Some(agent) = v.get("agent").and_then(|a| a.as_object()) {
        if let Some(s) = agent.get("name").and_then(|x| x.as_str()) {
            agent_name = s.chars().take(64).collect();
        }
        if let Some(s) = agent.get("version").and_then(|x| x.as_str()) {
            agent_version = s.chars().take(64).collect();
        }
        if let Some(s) = agent.get("platform").and_then(|x| x.as_str()) {
            agent_platform = s.chars().take(64).collect();
        }
    }
    Ok(RegisterPlaintext {
        v: version as i32,
        client_pub,
        client_share,
        issued_at_bd,
        ttl_seconds,
        agent_name,
        agent_version,
        agent_platform,
    })
}

pub fn build_deliver_aad(direction: u8, counter: u64, typ: &str, context: &str) -> Vec<u8> {
    let mut aad = Vec::new();
    append_le32(&mut aad, 1);
    aad.push(direction);
    append_le32(&mut aad, 8);
    append_u64_be(&mut aad, counter);
    let type_bytes = typ.as_bytes();
    append_le32(&mut aad, type_bytes.len() as u32);
    aad.extend_from_slice(type_bytes);
    let ctx_bytes = context.as_bytes();
    append_le32(&mut aad, ctx_bytes.len() as u32);
    aad.extend_from_slice(ctx_bytes);
    aad
}

fn decode_b64_fixed<const N: usize>(
    val: Option<&serde_json::Value>,
    first_byte: u8,
) -> crate::Result<[u8; N]> {
    use base64::Engine;
    let s = val
        .and_then(|x| x.as_str())
        .ok_or_else(|| crate::BridgeError::msg("Invalid envelope plaintext"))?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|_| crate::BridgeError::msg("Invalid envelope plaintext"))?;
    if bytes.len() != N {
        return Err(crate::BridgeError::msg("Invalid envelope plaintext"));
    }
    if first_byte != 0 && bytes[0] != first_byte {
        return Err(crate::BridgeError::msg("Invalid envelope plaintext"));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn append_length_prefixed(out: &mut Vec<u8>, data: &[u8]) {
    append_le32(out, data.len() as u32);
    out.extend_from_slice(data);
}

fn append_le32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_le_bytes());
}

fn append_u32_be(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

fn append_u64_be(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcript_length_is_238() {
        let nonce = [1u8; 16];
        let pubk = [0x04u8; 65];
        let share = [2u8; 32];
        let sid = [3u8; 16];
        let bshare = [4u8; 32];
        let t = build_transcript(&nonce, &pubk, &share, &sid, &bshare, 9638.0, 1_700_000_000, 3600)
            .unwrap();
        assert_eq!(t.len(), 238);
        assert_eq!(&t[..25], TRANSCRIPT_HEADER);
    }
}
