use std::sync::Arc;
use std::time::Instant;

use zeroize::Zeroizing;

use crate::credentials::EphemeralStore;
use crate::geo::{GeoEngine, GeoSource};
use crate::handler::ConnectionHandler;
use crate::identity::BridgeIdentity;
use crate::paths::Paths;
use crate::Result;

pub struct Bridge {
    paths: Paths,
    identity: Arc<dyn BridgeIdentity>,
    ecies_key: Zeroizing<[u8; 32]>,
    store: Arc<EphemeralStore>,
    geo: Arc<GeoEngine>,
    started: Instant,
    peer_attest: Option<Arc<dyn Fn(&std::os::unix::net::UnixStream) -> crate::handler::PeerInfo + Send + Sync>>,
}

impl Bridge {
    pub fn new(
        paths: Paths,
        identity: Arc<dyn BridgeIdentity>,
        geo_source: Arc<dyn GeoSource>,
    ) -> Result<Self> {
        paths.bootstrap()?;
        paths.verify_socket_squatting()?;
        let ecies_key = crate::ecies::load_or_create_ecies_key(&paths.ecies_privkey)?;
        let kind = identity.kind();
        std::fs::write(&paths.bridge_identity_kind, kind.as_str())?;
        if !kind.is_hardware_backed() {
            tracing::warn!("bridge identity is software-backed ({})", kind.as_str());
        } else {
            tracing::info!("bridge identity: {}", kind.as_str());
        }
        let geo = GeoEngine::new(geo_source);
        geo.load_zones_from_file(&paths.geo_zones);
        geo.load_acl_from_file(&paths.geo_acl);
        let geo = Arc::new(geo);
        Ok(Self {
            paths,
            identity,
            ecies_key,
            store: Arc::new(EphemeralStore::new()),
            geo,
            started: Instant::now(),
            peer_attest: None,
        })
    }

    pub fn set_peer_attest(
        &mut self,
        f: Arc<dyn Fn(&std::os::unix::net::UnixStream) -> crate::handler::PeerInfo + Send + Sync>,
    ) {
        self.peer_attest = Some(f);
    }

    pub fn peer_for_stream(&self, stream: &std::os::unix::net::UnixStream) -> crate::handler::PeerInfo {
        if let Some(f) = &self.peer_attest {
            return f(stream);
        }
        crate::handler::PeerInfo::from_stream(stream)
    }

    pub fn paths(&self) -> &Paths {
        &self.paths
    }

    pub fn identity(&self) -> &dyn BridgeIdentity {
        self.identity.as_ref()
    }

    pub fn identity_kind_str(&self) -> &str {
        self.identity.kind().as_str()
    }

    pub fn store(&self) -> &EphemeralStore {
        &self.store
    }

    pub fn geo(&self) -> &GeoEngine {
        &self.geo
    }

    pub fn ecies_private_key(&self) -> &[u8; 32] {
        &self.ecies_key
    }

    pub fn ecies_public_key_b64(&self) -> Result<String> {
        use base64::Engine;
        let pk = crate::ecies::ecies_public_key(&self.ecies_key)?;
        Ok(base64::engine::general_purpose::STANDARD.encode(pk))
    }

    pub fn enclave_public_key_b64(&self) -> Result<String> {
        use base64::Engine;
        let pk = self.identity.public_key();
        Ok(base64::engine::general_purpose::STANDARD.encode(pk))
    }

    pub fn ecies_fingerprint(&self) -> String {
        fp_label(&crate::ecies::ecies_public_key(&self.ecies_key).unwrap_or([0; 65]))
    }

    pub fn enclave_fingerprint(&self) -> String {
        fp_label(&self.identity.public_key())
    }

    pub fn uptime_seconds(&self) -> u64 {
        self.started.elapsed().as_secs()
    }

    pub fn new_handler(self: &Arc<Self>, peer: crate::handler::PeerInfo) -> ConnectionHandler {
        ConnectionHandler::new(Arc::clone(self), peer)
    }

    pub fn run_socket_server(self: Arc<Self>) -> Result<()> {
        let socket_path = self.paths.primary_socket.clone();
        let server = crate::socket::SocketServer::new(self, socket_path);
        server.run_blocking()
    }
}

fn fp_label(pub65: &[u8; 65]) -> String {
    use sha2::{Digest, Sha256};
    let d = Sha256::digest(pub65);
    format!("sha256:{}", hex::encode(&d[..8]))
}
