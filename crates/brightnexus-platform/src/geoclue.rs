//! GeoClue2 D-Bus geo source (optional `geoclue` feature).

use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use brightnexus_core::geo::{brightdate_now, wgs84_to_ecef, GeoFix, GeoSource, GeoSourceStatus};
use zbus::proxy;
use zbus::zvariant::OwnedObjectPath;
use zbus::Connection;

pub use crate::geo_source::IpGeoSource;

pub struct GeoClueGeoSource {
    last_fix: Mutex<Option<GeoFix>>,
}

impl GeoClueGeoSource {
    pub fn new() -> Self {
        Self {
            last_fix: Mutex::new(None),
        }
    }

    async fn fetch_from_geoclue(&self) -> brightnexus_core::Result<GeoFix> {
        let connection = Connection::system().await.map_err(|e| {
            brightnexus_core::BridgeError::msg(format!("D-Bus system bus unavailable: {e}"))
        })?;

        let manager = GeoClueManagerProxy::new(&connection)
            .await
            .map_err(|e| brightnexus_core::BridgeError::msg(format!("GeoClue manager: {e}")))?;

        let client_path = manager
            .create_client()
            .await
            .map_err(|e| brightnexus_core::BridgeError::msg(format!("GeoClue CreateClient: {e}")))?;

        let client = GeoClueClientProxy::builder(&connection)
            .path(client_path.as_str())
            .map_err(|e| brightnexus_core::BridgeError::msg(format!("GeoClue client path: {e}")))?
            .build()
            .await
            .map_err(|e| brightnexus_core::BridgeError::msg(format!("GeoClue client proxy: {e}")))?;

        client
            .start()
            .await
            .map_err(|e| brightnexus_core::BridgeError::msg(format!("GeoClue Start: {e}")))?;

        let location_path = wait_for_location(&client, Duration::from_secs(15)).await?;

        let location = GeoClueLocationProxy::builder(&connection)
            .path(location_path.as_str())
            .map_err(|e| brightnexus_core::BridgeError::msg(format!("GeoClue location path: {e}")))?
            .build()
            .await
            .map_err(|e| brightnexus_core::BridgeError::msg(format!("GeoClue location proxy: {e}")))?;

        let lat = location
            .latitude()
            .await
            .map_err(|e| brightnexus_core::BridgeError::msg(format!("GeoClue Latitude: {e}")))?;
        let lon = location
            .longitude()
            .await
            .map_err(|e| brightnexus_core::BridgeError::msg(format!("GeoClue Longitude: {e}")))?;
        let accuracy = location
            .accuracy()
            .await
            .unwrap_or(100.0);
        let alt = location.altitude().await.unwrap_or(0.0);

        let _ = client.stop().await;

        let (x, y, z) = wgs84_to_ecef(lat, lon, alt);
        Ok(GeoFix {
            brightdate: brightdate_now(),
            wgs84_lat: lat,
            wgs84_lon: lon,
            wgs84_alt_m: Some(alt),
            ecef_x_m: x,
            ecef_y_m: y,
            ecef_z_m: z,
            accuracy_m: accuracy,
        })
    }
}

async fn wait_for_location(
    client: &GeoClueClientProxy<'_>,
    timeout: Duration,
) -> brightnexus_core::Result<OwnedObjectPath> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Ok(path) = client.location().await {
            if !path.as_str().is_empty() && path.as_str() != "/" {
                return Ok(path);
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(brightnexus_core::BridgeError::msg(
                "GeoClue location timeout (permission denied or daemon unavailable)",
            ));
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[proxy(
    interface = "org.freedesktop.GeoClue2.Manager",
    default_service = "org.freedesktop.GeoClue2",
    default_path = "/org/freedesktop/GeoClue2/Manager"
)]
trait GeoClueManager {
    fn create_client(&self) -> zbus::Result<OwnedObjectPath>;
}

#[proxy(
    interface = "org.freedesktop.GeoClue2.Client",
    default_service = "org.freedesktop.GeoClue2"
)]
trait GeoClueClient {
    fn start(&self) -> zbus::Result<()>;
    fn stop(&self) -> zbus::Result<()>;
    #[zbus(property)]
    fn location(&self) -> zbus::Result<OwnedObjectPath>;
}

#[proxy(
    interface = "org.freedesktop.GeoClue2.Location",
    default_service = "org.freedesktop.GeoClue2"
)]
trait GeoClueLocation {
    #[zbus(property)]
    fn latitude(&self) -> zbus::Result<f64>;
    #[zbus(property)]
    fn longitude(&self) -> zbus::Result<f64>;
    #[zbus(property)]
    fn accuracy(&self) -> zbus::Result<f64>;
    #[zbus(property)]
    fn altitude(&self) -> zbus::Result<f64>;
}

#[async_trait]
impl GeoSource for GeoClueGeoSource {
    fn current_fix(&self) -> Option<GeoFix> {
        self.last_fix.lock().unwrap().clone()
    }

    async fn request_refresh(&self, timeout_ms: u64) -> brightnexus_core::Result<GeoFix> {
        let _ = timeout_ms;
        let fix = self.fetch_from_geoclue().await?;
        *self.last_fix.lock().unwrap() = Some(fix.clone());
        Ok(fix)
    }

    fn status(&self) -> GeoSourceStatus {
        let has_fix = self.last_fix.lock().unwrap().is_some();
        GeoSourceStatus {
            alive: has_fix,
            fix_age_seconds: if has_fix { Some(0.0) } else { None },
            source_name: "GeoClueGeoSource".into(),
        }
    }
}
