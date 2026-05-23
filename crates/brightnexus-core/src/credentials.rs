use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialPayload {
    pub typ: String,
    pub context: String,
    pub ttl: i64,
    #[serde(flatten)]
    pub body: Value,
}

#[derive(Debug, Clone)]
pub struct CredentialEntry {
    pub payload: CredentialPayload,
    pub expires_at: DateTime<Utc>,
    pub session_id_hex: String,
    pub provider_label: Option<String>,
}

pub type StoreChangeCallback = Arc<dyn Fn() + Send + Sync>;

pub struct EphemeralStore {
    inner: Arc<Mutex<StoreInner>>,
    on_change: Mutex<Option<StoreChangeCallback>>,
}

struct StoreInner {
    entries: std::collections::HashMap<String, CredentialEntry>,
}

impl Clone for EphemeralStore {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            on_change: Mutex::new(None),
        }
    }
}

impl EphemeralStore {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(StoreInner {
                entries: std::collections::HashMap::new(),
            })),
            on_change: Mutex::new(None),
        }
    }

    pub fn set_on_change(&self, cb: StoreChangeCallback) {
        *self.on_change.lock().unwrap() = Some(cb);
    }

    pub fn insert(
        &self,
        payload: CredentialPayload,
        session_id_hex: String,
        provider_label: Option<String>,
        expires_at: DateTime<Utc>,
    ) {
        let entry = CredentialEntry {
            payload: payload.clone(),
            expires_at,
            session_id_hex,
            provider_label,
        };
        {
            let mut inner = self.inner.lock().unwrap();
            inner.entries.insert(payload.context.clone(), entry);
        }
        self.notify();
    }

    pub fn remove_all(&self) {
        let mut inner = self.inner.lock().unwrap();
        if !inner.entries.is_empty() {
            inner.entries.clear();
            drop(inner);
            self.notify();
        }
    }

    pub fn active_entries(&self) -> Vec<CredentialEntry> {
        let now = Utc::now();
        let inner = self.inner.lock().unwrap();
        let mut v: Vec<_> = inner
            .entries
            .values()
            .filter(|e| e.expires_at > now)
            .cloned()
            .collect();
        v.sort_by(|a, b| a.payload.context.cmp(&b.payload.context));
        v
    }

    pub fn sweep(&self) {
        let now = Utc::now();
        let mut inner = self.inner.lock().unwrap();
        let before = inner.entries.len();
        inner.entries.retain(|_, e| e.expires_at > now);
        if inner.entries.len() != before {
            drop(inner);
            self.notify();
        }
    }

    fn notify(&self) {
        if let Some(cb) = self.on_change.lock().unwrap().as_ref() {
            cb();
        }
    }
}

impl Default for EphemeralStore {
    fn default() -> Self {
        Self::new()
    }
}

pub fn decode_payload(plaintext: &[u8], wire_type: &str, wire_context: &str) -> crate::Result<CredentialPayload> {
    let mut v: Value = serde_json::from_slice(plaintext)?;
    let ttl = v.get("ttl").and_then(|x| x.as_i64()).unwrap_or(300);
    let typ = v
        .get("type")
        .and_then(|x| x.as_str())
        .unwrap_or(wire_type)
        .to_string();
    let context = v
        .get("context")
        .and_then(|x| x.as_str())
        .unwrap_or(wire_context)
        .to_string();
    if let Some(obj) = v.as_object_mut() {
        obj.remove("type");
        obj.remove("context");
        obj.remove("ttl");
    }
    Ok(CredentialPayload {
        typ,
        context,
        ttl,
        body: v,
    })
}

pub struct DeliverRateLimiter {
    threshold: u32,
    window: Duration,
    failures: Mutex<(u32, Instant)>,
}

impl DeliverRateLimiter {
    pub fn new(threshold: u32, window_seconds: u64) -> Self {
        Self {
            threshold,
            window: Duration::from_secs(window_seconds),
            failures: Mutex::new((0, Instant::now())),
        }
    }

    pub fn reset(&self) {
        *self.failures.lock().unwrap() = (0, Instant::now());
    }

    pub fn record_failure(&self) -> bool {
        let mut guard = self.failures.lock().unwrap();
        let now = Instant::now();
        if now.duration_since(guard.1) > self.window {
            *guard = (1, now);
            return false;
        }
        guard.0 += 1;
        guard.0 >= self.threshold
    }
}
