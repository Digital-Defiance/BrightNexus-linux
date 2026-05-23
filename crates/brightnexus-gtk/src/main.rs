mod app;
mod geo_prompt;
mod settings;
mod tray;

use std::sync::Arc;

use brightnexus_core::paths::Paths;
use brightnexus_core::Bridge;
use brightnexus_platform::{select_bridge_identity, select_geo_source};
use gtk4::prelude::*;
use gtk4::{gio, glib};
use libadwaita as adw;
use tracing_subscriber::EnvFilter;

fn main() -> glib::ExitCode {
    if let Err(e) = run() {
        eprintln!("brightnexus: {e}");
        glib::ExitCode::FAILURE
    } else {
        glib::ExitCode::SUCCESS
    }
}

fn run() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("brightnexus=info".parse()?))
        .init();

    let paths = Paths::new();
    paths.bootstrap()?;
    let identity = select_bridge_identity(&paths)?;
    let geo_source = select_geo_source();
    let mut bridge = Bridge::new(paths, identity, geo_source)?;
    bridge.set_peer_attest(Arc::new(|s| brightnexus_platform::attestation::attest_stream(s)));
    let bridge = Arc::new(bridge);
    let bridge_bg = Arc::clone(&bridge);

    std::thread::spawn(move || {
        if let Err(e) = bridge_bg.run_socket_server() {
            tracing::error!("socket server failed: {e}");
        }
    });

    let app = adw::Application::builder()
        .application_id("org.digitaldefiance.brightchain.BrightNexus")
        .build();

    let bridge_ui = Arc::clone(&bridge);
    app.connect_activate(move |app| {
        app::activate(app, bridge_ui.clone());
    });

    app.run();
    Ok(())
}
