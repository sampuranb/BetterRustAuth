// Types for telemetry — mirrors packages/telemetry/src/types.ts

use std::sync::Arc;

use serde::{Deserialize, Serialize};

/// Detection info for runtime, framework, database, etc.
///
/// Maps to TS `DetectionInfo`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionInfo {
    pub name: String,
    pub version: Option<String>,
}

/// A telemetry event.
///
/// Maps to TS `TelemetryEvent`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TelemetryEvent {
    /// Event type, e.g. "init"
    #[serde(rename = "type")]
    pub event_type: String,
    /// Anonymous project identifier
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anonymous_id: Option<String>,
    /// Event payload
    pub payload: serde_json::Value,
}

/// Context passed to telemetry creation.
///
/// Maps to TS `TelemetryContext`.
pub struct TelemetryContext {
    /// Custom tracking function — overrides the HTTP endpoint.
    pub custom_track: Option<Arc<dyn Fn(TelemetryEvent) + Send + Sync>>,
    /// Database identifier for config reporting.
    pub database: Option<String>,
    /// Adapter identifier for config reporting.
    pub adapter: Option<String>,
    /// Skip test environment check.
    pub skip_test_check: bool,
}

impl Default for TelemetryContext {
    fn default() -> Self {
        Self {
            custom_track: None,
            database: None,
            adapter: None,
            skip_test_check: false,
        }
    }
}
