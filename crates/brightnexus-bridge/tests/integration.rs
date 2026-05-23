use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use base64::Engine;
use brightnexus_core::ecies::{ecies_encrypt, ecies_public_key};
use brightnexus_core::paths::Paths;
use brightnexus_core::socket::extract_json_object;
use brightnexus_core::session::{CLIENT_NONCE_LEN, SHARE_LEN};
use brightnexus_core::Bridge;
use brightnexus_platform::file_identity::FileBridgeIdentity;
use brightnexus_platform::select_geo_source;
use rand::RngCore;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use tempfile::TempDir;

fn read_one_json(stream: &mut UnixStream) -> serde_json::Value {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = stream.read(&mut chunk).unwrap();
        assert!(n > 0, "unexpected EOF");
        buf.extend_from_slice(&chunk[..n]);
        if let Some((msg, _)) = extract_json_object(&buf) {
            return serde_json::from_slice(&msg).unwrap();
        }
    }
}

fn test_paths(tmp: &TempDir) -> Paths {
    let mut paths = Paths::new();
    paths.tool_dir = tmp.path().join("brightnexus");
    paths.umbrella = tmp.path().join(".brightchain");
    paths.primary_socket = paths.tool_dir.join("brightnexus.sock");
    paths.ecies_privkey = paths.tool_dir.join("ecies-privkey.bin");
    paths.bridge_identity_key = paths.tool_dir.join("bridge-identity.key");
    paths.bridge_identity_pub = paths.tool_dir.join("bridge-identity.pub");
    paths.bridge_identity_kind = paths.tool_dir.join("bridge-identity.kind");
    paths.geo_zones = paths.tool_dir.join("geo-zones.json");
    paths
}

static GEO_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct GeoEnvGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    prev: Option<String>,
}

impl GeoEnvGuard {
    fn set_fixed() -> Self {
        let lock = GEO_ENV_LOCK.lock().unwrap();
        let prev = std::env::var("BRIGHTNEXUS_GEO_SOURCE").ok();
        std::env::set_var("BRIGHTNEXUS_GEO_SOURCE", "fixed");
        Self { prev, _lock: lock }
    }
}

impl Drop for GeoEnvGuard {
    fn drop(&mut self) {
        match &self.prev {
            Some(v) => std::env::set_var("BRIGHTNEXUS_GEO_SOURCE", v),
            None => std::env::remove_var("BRIGHTNEXUS_GEO_SOURCE"),
        }
    }
}

fn spawn_bridge(paths: Paths) -> (Arc<Bridge>, std::path::PathBuf) {
    let _geo_env = GeoEnvGuard::set_fixed();
    paths.bootstrap().unwrap();
    let identity = Arc::new(FileBridgeIdentity::open_or_create(&paths).unwrap());
    let geo = select_geo_source();
    let bridge = Arc::new(Bridge::new(paths.clone(), identity, geo).unwrap());
    let zones = serde_json::json!({
        "zones": [{
            "name": "sf",
            "lat": 37.7749,
            "lon": -122.4194,
            "radius_m": 5000.0
        }]
    });
    std::fs::write(&paths.geo_zones, serde_json::to_string(&zones).unwrap()).unwrap();
    bridge.geo().load_zones_from_file(&paths.geo_zones);

    let socket_path = paths.primary_socket.clone();
    thread::spawn({
        let bridge = Arc::clone(&bridge);
        move || {
            let _ = bridge.run_socket_server();
        }
    });
    thread::sleep(Duration::from_millis(150));
    (bridge, socket_path)
}

#[test]
fn heartbeat_and_version_over_unix_socket() {
    let tmp = TempDir::new().unwrap();
    let paths = test_paths(&tmp);
    let (_bridge, socket_path) = spawn_bridge(paths);

    let mut stream = UnixStream::connect(&socket_path).unwrap();
    stream.write_all(br#"{"cmd":"HEARTBEAT"}"#).unwrap();
    let v = read_one_json(&mut stream);
    assert_eq!(v["ok"], true);
    assert_eq!(v["service"], "enclave-bridge");

    stream.write_all(br#"{"cmd":"INFO"}"#).unwrap();
    let info = read_one_json(&mut stream);
    assert_eq!(info["app"], "brightnexus");
    assert_eq!(info["brightlinkProtocolVersion"], 1);
    assert!(info.get("bridgeIdentityKind").is_some());
}

#[test]
fn get_public_keys_and_enclave_key() {
    let tmp = TempDir::new().unwrap();
    let paths = test_paths(&tmp);
    let (_bridge, socket_path) = spawn_bridge(paths);

    let mut stream = UnixStream::connect(&socket_path).unwrap();
    for cmd in ["GET_PUBLIC_KEY", "GET_ENCLAVE_PUBLIC_KEY"] {
        stream
            .write_all(format!(r#"{{"cmd":"{cmd}"}}"#).as_bytes())
            .unwrap();
        let v = read_one_json(&mut stream);
        let pk = v["publicKey"].as_str().unwrap();
        let decoded = base64::engine::general_purpose::STANDARD.decode(pk).unwrap();
        assert_eq!(decoded.len(), 65);
        assert_eq!(decoded[0], 0x04);
    }
}

#[test]
fn link_geo_status_and_get() {
    let tmp = TempDir::new().unwrap();
    let paths = test_paths(&tmp);
    let (_bridge, socket_path) = spawn_bridge(paths);

    let mut stream = UnixStream::connect(&socket_path).unwrap();
    stream
        .write_all(br#"{"cmd":"LINK_GEO_STATUS"}"#)
        .unwrap();
    let status = read_one_json(&mut stream);
    assert_eq!(status["ok"], true);
    assert_eq!(status["alive"], true);

    stream
        .write_all(br#"{"cmd":"LINK_GEO_GET","format":"both"}"#)
        .unwrap();
    let v = read_one_json(&mut stream);
    assert_eq!(v["ok"], true);
    assert!(v["position"]["wgs84"].is_object());
    assert!(v["position"]["brightspace"].is_object());
}

#[test]
fn link_geo_proximity_in_zone() {
    let tmp = TempDir::new().unwrap();
    let paths = test_paths(&tmp);
    let (_bridge, socket_path) = spawn_bridge(paths);

    let mut stream = UnixStream::connect(&socket_path).unwrap();
    stream
        .write_all(br#"{"cmd":"LINK_GEO_PROXIMITY","zone":"sf"}"#)
        .unwrap();
    let v = read_one_json(&mut stream);
    assert_eq!(v["ok"], true);
    assert_eq!(v["in_zone"], true);
}

#[test]
fn link_register_minimal_client_crypto() {
    let tmp = TempDir::new().unwrap();
    let paths = test_paths(&tmp);
    let (bridge, socket_path) = spawn_bridge(paths);

    let secp = Secp256k1::new();
    let mut rng = rand::thread_rng();
    let client_secret = SecretKey::new(&mut rng);
    let client_pub = PublicKey::from_secret_key(&secp, &client_secret);
    let mut client_pub65 = [0u8; 65];
    client_pub65.copy_from_slice(&client_pub.serialize_uncompressed());

    let bridge_pub = ecies_public_key(bridge.ecies_private_key()).unwrap();
    let client_share = [0x22u8; SHARE_LEN];
    let plaintext = serde_json::json!({
        "v": 1,
        "clientPub": base64::engine::general_purpose::STANDARD.encode(client_pub65),
        "clientShare": base64::engine::general_purpose::STANDARD.encode(client_share),
        "issuedAtBd": 9638.0,
        "ttlSeconds": 3600,
        "agent": {"name": "test", "version": "0.1", "platform": "linux"}
    });
    let envelope = ecies_encrypt(&bridge_pub, plaintext.to_string().as_bytes()).unwrap();

    let mut client_nonce = [0u8; CLIENT_NONCE_LEN];
    rng.fill_bytes(&mut client_nonce);

    let mut stream = UnixStream::connect(&socket_path).unwrap();
    let req = serde_json::json!({
        "cmd": "LINK_REGISTER",
        "protocolVersion": 1,
        "clientNonce": base64::engine::general_purpose::STANDARD.encode(client_nonce),
        "envelope": base64::engine::general_purpose::STANDARD.encode(envelope),
    });
    stream
        .write_all(serde_json::to_vec(&req).unwrap().as_slice())
        .unwrap();
    let v = read_one_json(&mut stream);
    assert_eq!(v["ok"], true, "register failed: {v}");
    assert!(v.get("sessionId").is_some());
    assert!(v.get("responseEnvelope").is_some());
    assert!(v.get("transcriptSig").is_some());
}

#[test]
fn reserved_commands_return_not_implemented() {
    let tmp = TempDir::new().unwrap();
    let paths = test_paths(&tmp);
    let (_bridge, socket_path) = spawn_bridge(paths);

    let mut stream = UnixStream::connect(&socket_path).unwrap();
    for cmd in ["LINK_PUSH", "LINK_AUDIT_EMIT"] {
        stream
            .write_all(format!(r#"{{"cmd":"{cmd}"}}"#).as_bytes())
            .unwrap();
        let v = read_one_json(&mut stream);
        let err = v["error"].as_str().unwrap();
        assert!(err.contains("not implemented in this build"), "{err}");
    }
}
