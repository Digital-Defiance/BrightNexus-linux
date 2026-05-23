use std::env;
use std::path::PathBuf;
use std::os::unix::fs::FileTypeExt;

/// Canonical filesystem layout per RFC / macOS BrightNexus.
#[derive(Clone)]
pub struct Paths {
    pub umbrella: PathBuf,
    pub tool_dir: PathBuf,
    pub primary_socket: PathBuf,
    pub ecies_privkey: PathBuf,
    pub totp_config: PathBuf,
    pub geo_acl: PathBuf,
    pub geo_acl_sig: PathBuf,
    pub geo_acl_session: PathBuf,
    pub geo_zones: PathBuf,
    pub geo_zones_sig: PathBuf,
    pub geo_policy: PathBuf,
    pub attestation_pins: PathBuf,
    pub bridge_identity_key: PathBuf,
    pub bridge_identity_pub: PathBuf,
    pub bridge_identity_kind: PathBuf,
}

impl Paths {
    pub fn new() -> Self {
        let home = dirs_home();
        let umbrella = home.join(".brightchain");
        let tool_dir = umbrella.join("brightnexus");
        Self {
            primary_socket: env::var("BRIGHTNEXUS_SOCKET")
                .map(PathBuf::from)
                .unwrap_or_else(|_| tool_dir.join("brightnexus.sock")),
            ecies_privkey: tool_dir.join("ecies-privkey.bin"),
            totp_config: tool_dir.join("totp-config.json"),
            geo_acl: tool_dir.join("geo-acl.json"),
            geo_acl_sig: tool_dir.join("geo-acl.sig"),
            geo_acl_session: tool_dir.join("geo-acl-session.json"),
            geo_zones: tool_dir.join("geo-zones.json"),
            geo_zones_sig: tool_dir.join("geo-zones.sig"),
            geo_policy: tool_dir.join("geo-policy.json"),
            attestation_pins: tool_dir.join("attestation-pins.json"),
            bridge_identity_key: tool_dir.join("bridge-identity.key"),
            bridge_identity_pub: tool_dir.join("bridge-identity.pub"),
            bridge_identity_kind: tool_dir.join("bridge-identity.kind"),
            umbrella,
            tool_dir,
        }
    }

    pub fn bootstrap(&self) -> crate::Result<()> {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        for dir in [&self.umbrella, &self.tool_dir] {
            if !dir.exists() {
                fs::create_dir_all(dir)?;
            }
            let mut perms = fs::metadata(dir)?.permissions();
            perms.set_mode(0o700);
            fs::set_permissions(dir, perms)?;
        }
        Ok(())
    }

    pub fn verify_socket_squatting(&self) -> crate::Result<()> {
        use std::fs;
        let p = &self.primary_socket;
        if p.exists() {
            let meta = fs::symlink_metadata(p)?;
            if !meta.file_type().is_socket() {
                return Err(crate::BridgeError::msg(format!(
                    "FATAL: socket path {} exists but is not a socket",
                    p.display()
                )));
            }
        }
        Ok(())
    }
}

fn dirs_home() -> PathBuf {
    env::var("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/tmp"))
}

impl Default for Paths {
    fn default() -> Self {
        Self::new()
    }
}
