//! Geo engine, ACL, zones — simplified port of macOS LinkGeoEngine.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::identity::BridgeIdentity;

pub const SPEED_OF_LIGHT: f64 = 299_792_458.0;
pub const WGS84_A: f64 = 6_378_137.0;
pub const WGS84_F: f64 = 1.0 / 298.257_223_563;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoFix {
    pub brightdate: f64,
    pub wgs84_lat: f64,
    pub wgs84_lon: f64,
    pub wgs84_alt_m: Option<f64>,
    pub ecef_x_m: f64,
    pub ecef_y_m: f64,
    pub ecef_z_m: f64,
    pub accuracy_m: f64,
}

impl GeoFix {
    pub fn brightspace(&self) -> (f64, f64, f64) {
        (
            self.ecef_x_m / SPEED_OF_LIGHT,
            self.ecef_y_m / SPEED_OF_LIGHT,
            self.ecef_z_m / SPEED_OF_LIGHT,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeoScope {
    Status,
    Proximity,
    Zone,
    Precise,
    Trajectory,
}

impl GeoScope {
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "geo:status" => Some(Self::Status),
            "geo:proximity" => Some(Self::Proximity),
            "geo:zone" => Some(Self::Zone),
            "geo:precise" => Some(Self::Precise),
            "geo:trajectory" => Some(Self::Trajectory),
            _ => None,
        }
    }

    pub fn wire_name(&self) -> &'static str {
        match self {
            Self::Status => "geo:status",
            Self::Proximity => "geo:proximity",
            Self::Zone => "geo:zone",
            Self::Precise => "geo:precise",
            Self::Trajectory => "geo:trajectory",
        }
    }
}

#[async_trait]
pub trait GeoSource: Send + Sync {
    fn current_fix(&self) -> Option<GeoFix>;
    async fn request_refresh(&self, timeout_ms: u64) -> crate::Result<GeoFix>;
    fn status(&self) -> GeoSourceStatus;
}

#[derive(Debug, Clone, Serialize)]
pub struct GeoSourceStatus {
    pub alive: bool,
    pub fix_age_seconds: Option<f64>,
    pub source_name: String,
}

pub struct FixedGeoSource {
    fix: GeoFix,
}

impl FixedGeoSource {
    pub fn san_francisco() -> Self {
        let lat = 37.7749;
        let lon = -122.4194;
        let (x, y, z) = wgs84_to_ecef(lat, lon, 0.0);
        Self {
            fix: GeoFix {
                brightdate: brightdate_now(),
                wgs84_lat: lat,
                wgs84_lon: lon,
                wgs84_alt_m: Some(0.0),
                ecef_x_m: x,
                ecef_y_m: y,
                ecef_z_m: z,
                accuracy_m: 100.0,
            },
        }
    }
}

#[async_trait]
impl GeoSource for FixedGeoSource {
    fn current_fix(&self) -> Option<GeoFix> {
        Some(self.fix.clone())
    }

    async fn request_refresh(&self, _timeout_ms: u64) -> crate::Result<GeoFix> {
        Ok(self.fix.clone())
    }

    fn status(&self) -> GeoSourceStatus {
        GeoSourceStatus {
            alive: true,
            fix_age_seconds: Some(0.0),
            source_name: "FixedGeoSource".into(),
        }
    }
}

pub fn wgs84_to_ecef(lat_deg: f64, lon_deg: f64, alt_m: f64) -> (f64, f64, f64) {
    let lat = lat_deg.to_radians();
    let lon = lon_deg.to_radians();
    let e2 = WGS84_F * (2.0 - WGS84_F);
    let sin_lat = lat.sin();
    let cos_lat = lat.cos();
    let cos_lon = lon.cos();
    let sin_lon = lon.sin();
    let n = WGS84_A / (1.0 - e2 * sin_lat * sin_lat).sqrt();
    let x = (n + alt_m) * cos_lat * cos_lon;
    let y = (n + alt_m) * cos_lat * sin_lon;
    let z = (n * (1.0 - e2) + alt_m) * sin_lat;
    (x, y, z)
}

pub fn brightdate_now() -> f64 {
    // Days since J2000.0 (2000-01-01T12:00:00 TT approx as Unix)
    const J2000_UNIX: f64 = 946_728_000.0;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();
    (now - J2000_UNIX) / 86400.0
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GeoAclFile {
    pub version: i32,
    pub bridge_key_id: String,
    pub entries: Vec<GeoAclEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoAclEntry {
    pub id: String,
    pub display_name: String,
    pub attestation_class: String,
    pub issuer_id: Option<String>,
    pub subject_id: Option<String>,
    pub expected_path: Option<String>,
    pub scopes: std::collections::HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoZoneDef {
    pub name: String,
    pub lat: f64,
    pub lon: f64,
    pub radius_m: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GeoZonesFile {
    pub zones: Vec<GeoZoneDef>,
}

/// Optional ACL prompt hook for UI integration and tests.
pub trait GeoAclPrompt: Send + Sync {
    fn allow_scope(&self, entry: &GeoAclEntry, scope: GeoScope) -> bool;
}

pub struct AllowAllGeoPrompt;

impl GeoAclPrompt for AllowAllGeoPrompt {
    fn allow_scope(&self, _entry: &GeoAclEntry, _scope: GeoScope) -> bool {
        true
    }
}

pub struct GeoEngine {
    source: Arc<dyn GeoSource>,
    acl: Mutex<GeoAclFile>,
    zones: Mutex<Vec<GeoZoneDef>>,
    zone_entered_at: Mutex<Option<(String, f64)>>,
    prompt: Mutex<Option<Arc<dyn GeoAclPrompt>>>,
}

impl GeoEngine {
    pub fn new(source: Arc<dyn GeoSource>) -> Self {
        Self {
            source,
            acl: Mutex::new(GeoAclFile {
                version: 1,
                bridge_key_id: String::new(),
                entries: vec![],
            }),
            zones: Mutex::new(vec![]),
            zone_entered_at: Mutex::new(None),
            prompt: Mutex::new(None),
        }
    }

    pub fn set_prompt_coordinator(&self, prompt: Arc<dyn GeoAclPrompt>) {
        *self.prompt.lock().unwrap() = Some(prompt);
    }

    pub fn load_zones_from_file(&self, path: &std::path::Path) {
        if let Ok(raw) = std::fs::read_to_string(path) {
            if let Ok(file) = serde_json::from_str::<GeoZonesFile>(&raw) {
                *self.zones.lock().unwrap() = file.zones;
            }
        }
    }

    pub fn load_acl_from_file(&self, path: &std::path::Path) {
        *self.acl.lock().unwrap() = load_acl(path);
    }

    pub fn set_zones(&self, zones: Vec<GeoZoneDef>) {
        *self.zones.lock().unwrap() = zones;
    }

    fn current_fix_or_none(&self) -> Option<GeoFix> {
        self.source.current_fix()
    }

    pub fn handle_status(&self) -> Value {
        let st = self.source.status();
        json!({
            "ok": true,
            "alive": st.alive,
            "fix_age_seconds": st.fix_age_seconds
        })
    }

    pub async fn handle_get(&self, format: &str) -> Value {
        let fix = match self.source.current_fix() {
            Some(f) => f,
            None => {
                if let Ok(f) = self.source.request_refresh(5000).await {
                    f
                } else {
                    return json!({"ok": false, "error": "geo: no fix available"});
                }
            }
        };
        let position = match format {
            "wgs84" => json!({
                "wgs84": {
                    "lat": fix.wgs84_lat,
                    "lon": fix.wgs84_lon,
                    "alt_m": fix.wgs84_alt_m
                }
            }),
            "brightspace" => {
                let (x, y, z) = fix.brightspace();
                json!({
                    "brightspace": { "x_bm": x, "y_bm": y, "z_bm": z }
                })
            }
            _ => {
                let (x, y, z) = fix.brightspace();
                json!({
                    "wgs84": {
                        "lat": fix.wgs84_lat,
                        "lon": fix.wgs84_lon,
                        "alt_m": fix.wgs84_alt_m
                    },
                    "brightspace": { "x_bm": x, "y_bm": y, "z_bm": z }
                })
            }
        };
        json!({
            "ok": true,
            "position": position,
            "accuracy_m": fix.accuracy_m,
            "brightdate": fix.brightdate
        })
    }

    pub async fn handle_refresh(&self) -> Value {
        match self.source.request_refresh(10000).await {
            Ok(fix) => json!({"ok": true, "accuracy_m": fix.accuracy_m, "brightdate": fix.brightdate}),
            Err(e) => json!({"ok": false, "error": format!("geo: refresh failed: {e}")}),
        }
    }

    pub fn handle_proximity(&self, zone_name: &str) -> Value {
        if zone_name.is_empty() {
            return json!({"ok": false, "error": "geo: missing zone name"});
        }
        let fix = match self.current_fix_or_none() {
            Some(f) => f,
            None => return json!({"ok": false, "error": "geo: no fix available"}),
        };
        let zones = self.zones.lock().unwrap();
        let Some(zone) = zones.iter().find(|z| z.name == zone_name) else {
            return json!({"ok": true, "in_zone": false, "unknown_zone": true});
        };
        let dist = haversine_m(fix.wgs84_lat, fix.wgs84_lon, zone.lat, zone.lon);
        json!({
            "ok": true,
            "in_zone": dist <= zone.radius_m,
            "distance_m": dist,
            "zone": zone_name
        })
    }

    pub fn handle_zone(&self) -> Value {
        let fix = match self.current_fix_or_none() {
            Some(f) => f,
            None => {
                return json!({
                    "ok": true,
                    "zone": null,
                    "dwell_seconds": 0,
                    "brightdate": brightdate_now()
                });
            }
        };
        let bd = brightdate_now();
        let zones = self.zones.lock().unwrap();
        for zone in zones.iter() {
            let dist = haversine_m(fix.wgs84_lat, fix.wgs84_lon, zone.lat, zone.lon);
            if dist <= zone.radius_m {
                let mut entered = self.zone_entered_at.lock().unwrap();
                let dwell_seconds = if entered
                    .as_ref()
                    .map(|(n, _)| n.as_str())
                    == Some(zone.name.as_str())
                {
                    (bd - entered.as_ref().unwrap().1) * 86400.0
                } else {
                    *entered = Some((zone.name.clone(), bd));
                    0.0
                };
                return json!({
                    "ok": true,
                    "zone": zone.name,
                    "dwell_seconds": dwell_seconds,
                    "brightdate": bd
                });
            }
        }
        *self.zone_entered_at.lock().unwrap() = None;
        json!({
            "ok": true,
            "zone": null,
            "dwell_seconds": 0,
            "brightdate": bd
        })
    }

    pub fn acl_allows_scope(&self, subject_id: &str, scope: GeoScope) -> bool {
        let acl = self.acl.lock().unwrap();
        let scope_name = scope.wire_name();
        let Some(entry) = acl.entries.iter().find(|e| {
            e.subject_id.as_deref() == Some(subject_id)
                || e.id == subject_id
                || e.display_name == subject_id
        }) else {
            return false;
        };
        if let Some(prompt) = self.prompt.lock().unwrap().as_ref() {
            if !prompt.allow_scope(entry, scope) {
                return false;
            }
        }
        entry.scopes.contains_key(scope_name)
    }
}

fn haversine_m(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let r = WGS84_A;
    let d_lat = (lat2 - lat1).to_radians();
    let d_lon = (lon2 - lon1).to_radians();
    let a = (d_lat / 2.0).sin().powi(2)
        + lat1.to_radians().cos() * lat2.to_radians().cos() * (d_lon / 2.0).sin().powi(2);
    let c = 2.0 * a.sqrt().atan2((1.0 - a).sqrt());
    r * c
}

pub fn load_acl(path: &std::path::Path) -> GeoAclFile {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

pub fn sign_acl(acl: &GeoAclFile, identity: &dyn BridgeIdentity) -> crate::Result<Vec<u8>> {
    let canonical = serde_json::to_vec(acl)?;
    identity.sign(&canonical)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn proximity_detects_zone_with_fixed_source() {
        let source = Arc::new(FixedGeoSource::san_francisco());
        let engine = GeoEngine::new(source);
        engine.set_zones(vec![GeoZoneDef {
            name: "sf".into(),
            lat: 37.7749,
            lon: -122.4194,
            radius_m: 5000.0,
        }]);
        let prox = engine.handle_proximity("sf");
        assert_eq!(prox["ok"], true);
        assert_eq!(prox["in_zone"], true);
    }

    #[test]
    fn acl_prompt_coordinator_can_deny() {
        struct DenyPrompt;
        impl GeoAclPrompt for DenyPrompt {
            fn allow_scope(&self, _: &GeoAclEntry, _: GeoScope) -> bool {
                false
            }
        }
        let source = Arc::new(FixedGeoSource::san_francisco());
        let engine = GeoEngine::new(source);
        let mut scopes = std::collections::HashMap::new();
        scopes.insert("geo:status".into(), "allow".into());
        let tmp = tempfile::tempdir().unwrap();
        let acl_path = tmp.path().join("geo-acl.json");
        let acl = GeoAclFile {
            version: 1,
            bridge_key_id: "test".into(),
            entries: vec![GeoAclEntry {
                id: "e1".into(),
                display_name: "agent".into(),
                attestation_class: "test".into(),
                issuer_id: None,
                subject_id: Some("agent-1".into()),
                expected_path: None,
                scopes,
            }],
        };
        std::fs::write(&acl_path, serde_json::to_string(&acl).unwrap()).unwrap();
        engine.load_acl_from_file(&acl_path);
        engine.set_prompt_coordinator(Arc::new(DenyPrompt));
        assert!(!engine.acl_allows_scope("agent-1", GeoScope::Status));
    }
}
