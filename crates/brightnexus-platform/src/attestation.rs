//! Linux peer attestation via SO_PEERCRED, /proc, and dpkg.

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Command;

use brightnexus_core::handler::PeerInfo;
use sha2::{Digest, Sha256};

const LINEAGE_CAP: usize = 8;

pub fn attest_stream(stream: &UnixStream) -> PeerInfo {
    #[cfg(target_os = "linux")]
    {
        if let Some(mut info) = peer_cred(stream) {
            enrich_linux(&mut info);
            return info;
        }
    }
    PeerInfo::default()
}

#[cfg(target_os = "linux")]
fn peer_cred(stream: &UnixStream) -> Option<PeerInfo> {
    use std::os::unix::io::AsFd;
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};

    let cred = getsockopt(stream.as_fd(), PeerCredentials).ok()?;
    let pid = cred.pid as u32;
    let exe = fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned());
    Some(PeerInfo {
        pid: Some(pid),
        uid: Some(cred.uid as u32),
        executable_path: exe.clone(),
        display_label: exe,
        ..Default::default()
    })
}

fn enrich_linux(info: &mut PeerInfo) {
    if let Some(path) = &info.executable_path {
        if let Ok(bytes) = fs::read(path) {
            let hash = Sha256::digest(&bytes);
            let _ = hash; // stored in attestation pins in full impl
        }
        if let Some((pkg, signed)) = dpkg_info(path) {
            info.attestation_class = if signed {
                "DpkgSigned".into()
            } else {
                "Unsigned".into()
            };
            info.subject_id = Some(pkg.clone());
            info.signature_valid = signed;
            info.display_label = Some(format!("{pkg} ({path})"));
            return;
        }
    }
    info.attestation_class = "Unsigned".into();
    info.signature_valid = false;
}

fn dpkg_info(path: &str) -> Option<(String, bool)> {
    let output = Command::new("dpkg-query")
        .args(["-S", path])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let pkg = stdout.split(':').next()?.trim().to_string();
    let verify = Command::new("dpkg-verify").arg(&pkg).output().ok()?;
    let signed = verify.status.success();
    Some((pkg, signed))
}

pub fn read_proc_environ(pid: u32) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Ok(mut f) = fs::File::open(format!("/proc/{pid}/environ")) {
        let mut buf = Vec::new();
        if f.read_to_end(&mut buf).is_ok() {
            for part in buf.split(|&b| b == 0) {
                if let Ok(s) = std::str::from_utf8(part) {
                    if let Some((k, v)) = s.split_once('=') {
                        map.insert(k.to_string(), v.to_string());
                    }
                }
            }
        }
    }
    map
}

pub fn lineage_pids(pid: u32) -> Vec<u32> {
    let mut out = vec![pid];
    let mut current = pid;
    for _ in 0..LINEAGE_CAP {
        let status = match fs::read_to_string(format!("/proc/{current}/status")) {
            Ok(s) => s,
            Err(_) => break,
        };
        let ppid = status
            .lines()
            .find(|l| l.starts_with("PPid:"))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        if ppid == 0 || out.contains(&ppid) {
            break;
        }
        out.push(ppid);
        current = ppid;
    }
    out
}

pub fn detect_ssh_session(lineage: &[u32]) -> Option<(String, String, u32)> {
    for &pid in lineage {
        let exe = fs::read_link(format!("/proc/{pid}/exe")).ok()?;
        let path = exe.to_string_lossy();
        if !path.contains("sshd") {
            continue;
        }
        if let Some((pkg, signed)) = dpkg_info(&path) {
            if signed && pkg.contains("openssh-server") {
                let env = read_proc_environ(pid);
                let conn = env.get("SSH_CONNECTION").cloned().unwrap_or_default();
                let parts: Vec<_> = conn.split_whitespace().collect();
                let host = parts.get(2).unwrap_or(&"").to_string();
                let user = env.get("USER").cloned().unwrap_or_default();
                return Some((user, host, pid));
            }
        }
    }
    None
}

pub fn is_openssh_server(path: &Path) -> bool {
    dpkg_info(&path.to_string_lossy())
        .map(|(pkg, signed)| signed && pkg.contains("openssh-server"))
        .unwrap_or(false)
}
