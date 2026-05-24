//! Per-connection protocol handler.

use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use chrono::{Duration, Utc};
use rand::RngCore;
use serde_json::{json, Value};
use crate::credentials::{decode_payload, DeliverRateLimiter};
use crate::ecies::{ecies_decrypt, ecies_encrypt};
use crate::policy::{self, PeerAttestationMode};
use crate::session::{
    build_deliver_aad, build_transcript, derive_session_key, parse_register_plaintext,
    SessionRecord, CLIENT_NONCE_LEN, GCM_IV_LEN, GCM_TAG_LEN, MAX_TTL_SECONDS, REPLAY_WINDOW,
    SESSION_ID_LEN, SHARE_LEN,
};
use crate::Bridge;

#[derive(Debug, Clone, Default)]
pub struct PeerInfo {
    pub pid: Option<u32>,
    pub uid: Option<u32>,
    pub executable_path: Option<String>,
    pub attestation_class: String,
    pub issuer_id: Option<String>,
    pub subject_id: Option<String>,
    pub signature_valid: bool,
    pub display_label: Option<String>,
}

impl PeerInfo {
    pub fn from_stream(stream: &UnixStream) -> Self {
        #[cfg(not(target_os = "linux"))]
        let _ = stream;
        #[cfg(target_os = "linux")]
        {
            if let Some(peer) = peer_cred_linux(stream) {
                return peer;
            }
        }
        Self::default()
    }
}

#[cfg(target_os = "linux")]
fn peer_cred_linux(stream: &UnixStream) -> Option<PeerInfo> {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};

    let cred = getsockopt(stream, PeerCredentials).ok()?;
    let pid = cred.pid() as u32;
    let exe = std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned());
    Some(PeerInfo {
        pid: Some(pid),
        uid: Some(cred.uid() as u32),
        executable_path: exe.clone(),
        attestation_class: "Unsigned".into(),
        display_label: exe,
        ..Default::default()
    })
}

pub struct ConnectionHandler {
    bridge: Arc<Bridge>,
    peer: PeerInfo,
    peer_public_key: Option<Vec<u8>>,
    session: Option<SessionRecord>,
    deliver_limiter: DeliverRateLimiter,
}

impl ConnectionHandler {
    pub fn new(bridge: Arc<Bridge>, peer: PeerInfo) -> Self {
        Self {
            bridge,
            peer,
            peer_public_key: None,
            session: None,
            deliver_limiter: DeliverRateLimiter::new(30, 60),
        }
    }

    pub fn handle_message(&mut self, data: Vec<u8>) -> Vec<u8> {
        let json: Value = match serde_json::from_slice(&data) {
            Ok(v) => v,
            Err(_) => return error_response("Invalid request format"),
        };
        let cmd = match json.get("cmd").and_then(|c| c.as_str()) {
            Some(c) => c,
            None => return error_response("Invalid request format"),
        };

        match cmd {
            "HEARTBEAT" => json_response(json!({
                "ok": true,
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "service": "enclave-bridge"
            })),
            "VERSION" | "INFO" => self.handle_version(),
            "STATUS" => json_response(json!({
                "ok": true,
                "peerPublicKeySet": self.peer_public_key.is_some(),
                "enclaveKeyAvailable": true,
                "bridgeIdentityKind": self.bridge.identity_kind_str()
            })),
            "METRICS" => json_response(json!({
                "uptimeSeconds": self.bridge.uptime_seconds(),
                "service": "enclave-bridge",
                "requestCounters": {}
            })),
            "GET_PUBLIC_KEY" => match self.bridge.ecies_public_key_b64() {
                Ok(pk) => json_response(json!({"publicKey": pk})),
                Err(e) => error_response(&format!("Failed to get ECIES public key: {e}")),
            },
            "GET_ENCLAVE_PUBLIC_KEY" => match self.bridge.enclave_public_key_b64() {
                Ok(pk) => json_response(json!({"publicKey": pk})),
                Err(e) => error_response(&format!("Failed to get Secure Enclave public key: {e}")),
            },
            "SET_PEER_PUBLIC_KEY" => {
                if let Some(pk) = json.get("publicKey").and_then(|v| v.as_str()) {
                    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(pk) {
                        self.peer_public_key = Some(bytes);
                        return json_response(json!({"ok": true}));
                    }
                }
                error_response("Missing or invalid publicKey")
            }
            "LIST_KEYS" => self.handle_list_keys(),
            "ENCLAVE_SIGN" => self.handle_enclave_sign(&json),
            "ENCLAVE_DECRYPT" => self.handle_enclave_decrypt(&json),
            "ENCLAVE_GENERATE_KEY" => error_response("ENCLAVE_GENERATE_KEY not implemented"),
            "ENCLAVE_ROTATE_KEY" => error_response("ENCLAVE_ROTATE_KEY not supported on this platform"),
            "ENABLE_TOTP" => error_response("TOTP not configured"),
            "EXPORT_KEY" => error_response("TOTP code required or invalid for this key"),
            "LINK_REGISTER" => self.handle_link_register(&json),
            "LINK_DELIVER" => self.handle_link_deliver(&json),
            "LINK_PUSH" => error_response("LINK_PUSH not implemented in this build"),
            "LINK_AUDIT_EMIT" => error_response("LINK_AUDIT_EMIT not implemented in this build"),
            "LINK_GEO_STATUS" => json_response(self.bridge.geo().handle_status()),
            "LINK_GEO_PROXIMITY" => {
                let zone = json.get("zone").and_then(|z| z.as_str()).unwrap_or("");
                json_response(self.bridge.geo().handle_proximity(zone))
            }
            "LINK_GEO_ZONE" => json_response(self.bridge.geo().handle_zone()),
            "LINK_GEO_GET" => {
                let fmt = json.get("format").and_then(|f| f.as_str()).unwrap_or("both");
                let rt = tokio::runtime::Handle::try_current();
                if let Ok(handle) = rt {
                    let geo = self.bridge.geo();
                    let resp = handle.block_on(geo.handle_get(fmt));
                    json_response(resp)
                } else {
                    let rt = tokio::runtime::Runtime::new().unwrap();
                    let resp = rt.block_on(self.bridge.geo().handle_get(fmt));
                    json_response(resp)
                }
            }
            "LINK_GEO_REFRESH" => {
                let rt = tokio::runtime::Runtime::new().unwrap();
                let resp = rt.block_on(self.bridge.geo().handle_refresh());
                json_response(resp)
            }
            _ => error_response(&format!("Unknown command: {cmd}")),
        }
    }

    fn handle_version(&self) -> Vec<u8> {
        json_response(json!({
            "appVersion": env!("CARGO_PKG_VERSION"),
            "build": env!("CARGO_PKG_VERSION"),
            "platform": "Linux",
            "uptimeSeconds": self.bridge.uptime_seconds(),
            "app": "brightnexus",
            "brightlinkProtocolVersion": 1,
            "bridgeIdentityKind": self.bridge.identity_kind_str()
        }))
    }

    fn handle_list_keys(&self) -> Vec<u8> {
        let ecies_fp = self.bridge.ecies_fingerprint();
        let enclave_fp = self.bridge.enclave_fingerprint();
        json_response(json!({
            "keys": [
                {
                    "id": "ecies-secp256k1",
                    "type": "ecies",
                    "publicKeyFingerprint": ecies_fp,
                    "isSecureEnclave": false,
                    "totpEnabled": false,
                    "totpProvisioningURI": ""
                },
                {
                    "id": "secure-enclave-p256",
                    "type": "p256",
                    "publicKeyFingerprint": enclave_fp,
                    "isSecureEnclave": self.bridge.identity().kind().is_hardware_backed(),
                    "totpEnabled": false,
                    "totpProvisioningURI": ""
                }
            ]
        }))
    }

    fn handle_enclave_sign(&self, json: &Value) -> Vec<u8> {
        let data_b64 = match json.get("data").and_then(|d| d.as_str()) {
            Some(s) => s,
            None => return error_response("Missing or invalid data to sign"),
        };
        let data = match base64::engine::general_purpose::STANDARD.decode(data_b64) {
            Ok(d) => d,
            Err(_) => return error_response("Missing or invalid data to sign"),
        };
        match self.bridge.identity().sign(&data) {
            Ok(sig) => json_response(json!({
                "signature": base64::engine::general_purpose::STANDARD.encode(sig)
            })),
            Err(e) => error_response(&format!("Signing failed: {e}")),
        }
    }

    fn handle_enclave_decrypt(&self, json: &Value) -> Vec<u8> {
        let data_b64 = match json.get("data").and_then(|d| d.as_str()) {
            Some(s) => s,
            None => return error_response("Missing or invalid data to decrypt"),
        };
        let data = match base64::engine::general_purpose::STANDARD.decode(data_b64) {
            Ok(d) => d,
            Err(_) => return error_response("Missing or invalid data to decrypt"),
        };
        self.decrypt_envelope(&data)
    }

    fn decrypt_envelope(&self, encrypted: &[u8]) -> Vec<u8> {
        match ecies_decrypt(self.bridge.ecies_private_key(), encrypted) {
            Ok(pt) => json_response(json!({
                "plaintext": base64::engine::general_purpose::STANDARD.encode(pt)
            })),
            Err(_) => error_response("Decryption failed"),
        }
    }

    fn handle_link_register(&mut self, json: &Value) -> Vec<u8> {
        if json.get("protocolVersion").and_then(|v| v.as_i64()) != Some(1) {
            return error_response("Unsupported BrightLink protocol version");
        }
        let client_nonce_b64 = match json.get("clientNonce").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return error_response("Missing clientNonce"),
        };
        let client_nonce: [u8; CLIENT_NONCE_LEN] =
            match decode_fixed_b64::<CLIENT_NONCE_LEN>(client_nonce_b64) {
            Ok(n) => n,
            Err(_) => return error_response("Missing clientNonce"),
        };
        let envelope_b64 = match json.get("envelope").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return error_response("Missing envelope"),
        };
        let envelope = match base64::engine::general_purpose::STANDARD.decode(envelope_b64) {
            Ok(e) => e,
            Err(_) => return error_response("Missing envelope"),
        };
        let decrypt_resp = self.decrypt_envelope(&envelope);
        let decrypt_json: Value = match serde_json::from_slice(&decrypt_resp) {
            Ok(v) => v,
            Err(_) => return error_response("Decryption failed"),
        };
        let plaintext_b64 = match decrypt_json.get("plaintext").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return error_response("Decryption failed"),
        };
        let plaintext = match base64::engine::general_purpose::STANDARD.decode(plaintext_b64) {
            Ok(p) => p,
            Err(_) => return error_response("Decryption failed"),
        };
        let parsed = match parse_register_plaintext(&plaintext) {
            Ok(p) => p,
            Err(_) => return error_response("Invalid envelope plaintext"),
        };
        if parsed.v != 1 {
            return error_response("Invalid envelope plaintext");
        }
        let now_unix = unix_now();
        let issued_at_unix = (parsed.issued_at_bd * 86400.0).round() as i64;
        if issued_at_unix - now_unix > 60 {
            return error_response("Stale registration");
        }
        let granted_ttl = parsed.ttl_seconds.clamp(0, MAX_TTL_SECONDS);
        let mut bridge_share = [0u8; SHARE_LEN];
        let mut session_id = [0u8; SESSION_ID_LEN];
        rand::thread_rng().fill_bytes(&mut bridge_share);
        rand::thread_rng().fill_bytes(&mut session_id);
        let session_key = match derive_session_key(
            &parsed.client_share,
            &bridge_share,
            &client_nonce,
            &session_id,
        ) {
            Ok(k) => k,
            Err(e) => return error_response(&format!("internal: K_session derivation failed: {e}")),
        };
        let transcript = match build_transcript(
            &client_nonce,
            &parsed.client_pub,
            &parsed.client_share,
            &session_id,
            &bridge_share,
            parsed.issued_at_bd,
            now_unix,
            granted_ttl,
        ) {
            Ok(t) => t,
            Err(e) => return error_response(&format!("internal: transcript construction failed: {e}")),
        };
        let transcript_sig = match self.bridge.identity().sign(&transcript) {
            Ok(s) => s,
            Err(e) => return error_response(&format!("internal: SEP transcript sign failed: {e}")),
        };
        let response_envelope = match ecies_encrypt(&parsed.client_pub, &bridge_share) {
            Ok(e) => e,
            Err(e) => {
                return error_response(&format!("internal: response envelope encryption failed: {e}"))
            }
        };
        if let Some(old) = self.session.take() {
            let mut o = old;
            o.wipe();
        }
        self.deliver_limiter.reset();
        self.session = Some(SessionRecord {
            session_id,
            session_key,
            bridge_issued_at_unix: now_unix,
            ttl_seconds: granted_ttl,
            agent_name: parsed.agent_name,
            agent_version: parsed.agent_version,
            agent_platform: parsed.agent_platform,
            outbound_counter: 0,
            last_inbound_counter: 0,
        });
        json_response(json!({
            "ok": true,
            "sessionId": base64::engine::general_purpose::STANDARD.encode(session_id),
            "bridgeIssuedAtUnix": now_unix,
            "ttlSeconds": granted_ttl,
            "responseEnvelope": base64::engine::general_purpose::STANDARD.encode(response_envelope),
            "transcriptSig": base64::engine::general_purpose::STANDARD.encode(transcript_sig),
            "bridgeIdentityKind": self.bridge.identity_kind_str()
        }))
    }

    fn handle_link_deliver(&mut self, json: &Value) -> Vec<u8> {
        let session = match self.session.as_mut() {
            Some(s) => s,
            None => return error_response("Session not registered on this connection"),
        };
        if unix_now() > session.expires_at_unix() {
            return error_response("Session expired");
        }
        if policy::policy().peer_attestation_mode == PeerAttestationMode::Enforce {
            if !self.peer.signature_valid {
                self.record_deliver_failure();
                return error_response("Peer attestation failed");
            }
        }
        let counter = match json.get("counter").and_then(|c| c.as_u64()) {
            Some(c) => c,
            None => {
                self.record_deliver_failure();
                return error_response("Missing counter");
            }
        };
        let typ = match json.get("type").and_then(|t| t.as_str()) {
            Some(t) => t.to_string(),
            None => {
                self.record_deliver_failure();
                return error_response("Missing type");
            }
        };
        let context = match json.get("context").and_then(|c| c.as_str()) {
            Some(c) => c.to_string(),
            None => {
                self.record_deliver_failure();
                return error_response("Missing context");
            }
        };
        let iv = match decode_b64_field(json.get("iv"), GCM_IV_LEN) {
            Ok(v) => v,
            Err(m) => {
                self.record_deliver_failure();
                return error_response(&m);
            }
        };
        let ct = match json.get("ciphertext").and_then(|c| c.as_str()) {
            Some(s) => match base64::engine::general_purpose::STANDARD.decode(s) {
                Ok(b) => b,
                Err(_) => {
                    self.record_deliver_failure();
                    return error_response("iv/ciphertext/authTag not base64");
                }
            },
            None => {
                self.record_deliver_failure();
                return error_response("Missing iv/ciphertext/authTag");
            }
        };
        let tag = match decode_b64_field(json.get("authTag"), GCM_TAG_LEN) {
            Ok(t) => t,
            Err(m) => {
                self.record_deliver_failure();
                return error_response(&m);
            }
        };
        if counter <= session.last_inbound_counter {
            self.record_deliver_failure();
            return error_response("Counter replayed");
        }
        if counter > session.last_inbound_counter + REPLAY_WINDOW {
            self.record_deliver_failure();
            return error_response("Counter out of replay window");
        }
        let aad = build_deliver_aad(0x01, counter, &typ, &context);
        let plaintext = match crate::crypto::aes_gcm_decrypt(&session.session_key, &iv, &aad, &ct, &tag) {
            Ok(p) => p,
            Err(_) => {
                self.record_deliver_failure();
                return error_response("AES-GCM authentication failed");
            }
        };
        let payload = match decode_payload(&plaintext, &typ, &context) {
            Ok(p) => p,
            Err(e) => {
                self.record_deliver_failure();
                return error_response(&format!("Invalid payload body: {e}"));
            }
        };
        let ceiling = policy::policy().credential_ttl_ceiling_seconds;
        let requested_ttl = if payload.ttl > 0 { payload.ttl } else { 300 };
        let resolved_ttl = requested_ttl.min(ceiling);
        let expires_at = Utc::now() + Duration::seconds(resolved_ttl);
        session.last_inbound_counter = counter;
        let session_id_hex = hex::encode(session.session_id);
        self.bridge.store().insert(
            payload.clone(),
            session_id_hex,
            self.peer.display_label.clone(),
            expires_at,
        );
        json_response(json!({
            "ok": true,
            "type": payload.typ,
            "context": payload.context
        }))
    }

    fn record_deliver_failure(&mut self) -> bool {
        if self.deliver_limiter.record_failure() {
            if let Some(mut s) = self.session.take() {
                s.wipe();
            }
            true
        } else {
            false
        }
    }
}

impl Drop for ConnectionHandler {
    fn drop(&mut self) {
        if let Some(mut s) = self.session.take() {
            s.wipe();
        }
    }
}

fn decode_fixed_b64<const N: usize>(s: &str) -> crate::Result<[u8; N]> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|_| crate::BridgeError::msg("decode"))?;
    if bytes.len() != N {
        return Err(crate::BridgeError::msg("length"));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn decode_b64_field(val: Option<&Value>, len: usize) -> Result<Vec<u8>, String> {
    let s = val.and_then(|v| v.as_str()).ok_or_else(|| "Missing iv/ciphertext/authTag".to_string())?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(s)
        .map_err(|_| "iv/ciphertext/authTag not base64".to_string())?;
    if bytes.len() != len {
        return Err(format!("field must be {len} bytes"));
    }
    Ok(bytes)
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

pub fn json_response(v: Value) -> Vec<u8> {
    serde_json::to_vec(&v).unwrap_or_default()
}

pub fn error_response(msg: &str) -> Vec<u8> {
    json_response(json!({"error": msg}))
}
