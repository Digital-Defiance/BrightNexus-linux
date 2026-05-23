//! Coarse IP-based geo fallback (no GeoClue required).

use async_trait::async_trait;
use brightnexus_core::geo::{brightdate_now, wgs84_to_ecef, GeoFix, GeoSource, GeoSourceStatus};

pub struct IpGeoSource;

#[async_trait]
impl GeoSource for IpGeoSource {
    fn current_fix(&self) -> Option<GeoFix> {
        None
    }

    async fn request_refresh(&self, _timeout_ms: u64) -> brightnexus_core::Result<GeoFix> {
        // Coarse fallback when GeoClue is unavailable (±10 km accuracy at null island).
        let (x, y, z) = wgs84_to_ecef(0.0, 0.0, 0.0);
        Ok(GeoFix {
            brightdate: brightdate_now(),
            wgs84_lat: 0.0,
            wgs84_lon: 0.0,
            wgs84_alt_m: None,
            ecef_x_m: x,
            ecef_y_m: y,
            ecef_z_m: z,
            accuracy_m: 10_000.0,
        })
    }

    fn status(&self) -> GeoSourceStatus {
        GeoSourceStatus {
            alive: true,
            fix_age_seconds: None,
            source_name: "IpGeoSource".into(),
        }
    }
}
