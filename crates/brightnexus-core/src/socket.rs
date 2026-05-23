//! Unix socket server with brace-framed JSON.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;
use std::thread;

use crate::bridge::Bridge;
use crate::Result;

pub struct SocketServer {
    bridge: Arc<Bridge>,
    socket_path: std::path::PathBuf,
}

impl SocketServer {
    pub fn new(bridge: Arc<Bridge>, socket_path: std::path::PathBuf) -> Self {
        Self {
            bridge,
            socket_path,
        }
    }

    pub fn run_blocking(self) -> Result<()> {
        let path = self.socket_path.clone();
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let listener = UnixListener::bind(&path)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        tracing::info!("listening on {}", path.display());

        for stream in listener.incoming() {
            match stream {
                Ok(s) => {
                    let bridge = Arc::clone(&self.bridge);
                    thread::spawn(move || {
                        if let Err(e) = serve_connection(bridge, s) {
                            tracing::debug!("connection ended: {e}");
                        }
                    });
                }
                Err(e) => tracing::warn!("accept error: {e}"),
            }
        }
        Ok(())
    }
}

fn serve_connection(bridge: Arc<Bridge>, mut stream: UnixStream) -> Result<()> {
    let peer = bridge.peer_for_stream(&stream);
    let mut handler = bridge.new_handler(peer);
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
        while let Some((msg, rest)) = extract_json_object(&buf) {
            buf = rest;
            let resp = handler.handle_message(msg);
            stream.write_all(&resp)?;
            stream.write_all(b"\n")?;
        }
    }
    Ok(())
}

/// Read until one complete top-level `{...}` object (brace counting).
pub fn extract_json_object(buf: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let start = buf.iter().position(|&b| b == b'{')?;
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escape = false;
    for (i, &b) in buf[start..].iter().enumerate() {
        if in_string {
            if escape {
                escape = false;
            } else if b == b'\\' {
                escape = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    let end = start + i + 1;
                    let msg = buf[start..end].to_vec();
                    let rest = buf[end..].to_vec();
                    return Some((msg, rest));
                }
            }
            _ => {}
        }
    }
    None
}

pub fn bind_test_socket(dir: &Path) -> Result<(UnixListener, std::path::PathBuf)> {
    let path = dir.join("test.sock");
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    let listener = UnixListener::bind(&path)?;
    Ok((listener, path))
}
