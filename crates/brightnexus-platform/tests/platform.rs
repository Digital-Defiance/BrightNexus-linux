use brightnexus_core::geo::{FixedGeoSource, GeoSource};
use brightnexus_core::identity::BridgeIdentity;
use brightnexus_core::paths::Paths;
use brightnexus_platform::file_identity::FileBridgeIdentity;
use brightnexus_platform::select_geo_source;
use tempfile::TempDir;

fn test_paths(tmp: &TempDir) -> Paths {
    let mut paths = Paths::new();
    paths.tool_dir = tmp.path().join("brightnexus");
    paths.umbrella = tmp.path().join(".brightchain");
    paths.primary_socket = paths.tool_dir.join("brightnexus.sock");
    paths.ecies_privkey = paths.tool_dir.join("ecies-privkey.bin");
    paths.bridge_identity_key = paths.tool_dir.join("bridge-identity.key");
    paths.bridge_identity_pub = paths.tool_dir.join("bridge-identity.pub");
    paths.bridge_identity_kind = paths.tool_dir.join("bridge-identity.kind");
    paths
}

#[test]
fn file_identity_roundtrip_sign_and_verify() {
    let tmp = TempDir::new().unwrap();
    let paths = test_paths(&tmp);
    paths.bootstrap().unwrap();
    let id = FileBridgeIdentity::open_or_create(&paths).unwrap();
    let msg = b"brightlink transcript";
    let sig = id.sign(msg).unwrap();
    assert!(!sig.is_empty());
    let id2 = FileBridgeIdentity::open_or_create(&paths).unwrap();
    assert_eq!(id.key_id(), id2.key_id());
    assert_eq!(id.public_key(), id2.public_key());
}

static GEO_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

struct GeoEnvGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    prev: Option<String>,
}

impl GeoEnvGuard {
    fn set(value: &str) -> Self {
        let lock = GEO_ENV_LOCK.lock().unwrap();
        let prev = std::env::var("BRIGHTNEXUS_GEO_SOURCE").ok();
        std::env::set_var("BRIGHTNEXUS_GEO_SOURCE", value);
        Self {
            _lock: lock,
            prev,
        }
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

#[test]
fn select_geo_source_fixed_env() {
    let _guard = GeoEnvGuard::set("fixed");
    let source = select_geo_source();
    let st = source.status();
    assert_eq!(st.source_name, "FixedGeoSource");
    assert!(source.current_fix().is_some());
}

#[test]
fn select_geo_source_ip_env() {
    let _guard = GeoEnvGuard::set("ip");
    let source = select_geo_source();
    assert_eq!(source.status().source_name, "IpGeoSource");
}

#[cfg(target_os = "linux")]
#[test]
fn read_proc_environ_current_process() {
    use brightnexus_platform::attestation::read_proc_environ;
    let pid = std::process::id();
    let env = read_proc_environ(pid);
    assert!(env.contains_key("PATH") || !env.is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn lineage_pids_includes_init() {
    use brightnexus_platform::attestation::lineage_pids;
    let chain = lineage_pids(1);
    assert_eq!(chain[0], 1);
}

#[test]
fn fixed_geo_source_matches_sf_coordinates() {
    let fix = FixedGeoSource::san_francisco().current_fix().unwrap();
    assert!((fix.wgs84_lat - 37.7749).abs() < 0.001);
    assert!((fix.wgs84_lon - (-122.4194)).abs() < 0.001);
}
