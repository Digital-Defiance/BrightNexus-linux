use std::sync::Arc;

use brightnexus_core::paths::Paths;
use brightnexus_core::Bridge;
use brightnexus_platform::attestation::attest_stream;
use brightnexus_platform::{select_bridge_identity, select_geo_source};
use tracing_subscriber::EnvFilter;

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("brightnexus=info".parse()?))
        .init();

    let paths = Paths::new();
    paths.bootstrap()?;
    let identity = select_bridge_identity(&paths)?;
    let geo_source = select_geo_source();
    let mut bridge = Bridge::new(paths, identity, geo_source)?;
    bridge.set_peer_attest(Arc::new(|s| attest_stream(s)));
    let bridge = Arc::new(bridge);
    bridge.run_socket_server()?;
    Ok(())
}
