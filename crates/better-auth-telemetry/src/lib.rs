// better-auth-telemetry — mirrors packages/telemetry/src
//
// Provides opt-in usage analytics for Better Auth.
// When enabled, collects anonymous configuration data and sends it to a
// configured endpoint. Mirrors the TS `@better-auth/telemetry` package 1:1.

pub mod detectors;
pub mod project_id;
pub mod types;

use std::sync::Arc;

use better_auth_core::options::BetterAuthOptions;
use tokio::sync::OnceCell;
use tracing;

use crate::detectors::{
    detect_auth_config, detect_database, detect_environment, detect_framework,
    detect_package_manager, detect_runtime, detect_system_info,
};
use crate::project_id::get_project_id;
use crate::types::{TelemetryContext, TelemetryEvent};

// Re-exports
pub use crate::types::{DetectionInfo, TelemetryContext as TelemetryCtx};

/// The telemetry client — holds configuration and publish method.
///
/// Maps to the TS return type of `createTelemetry()`.
pub struct Telemetry {
    enabled: bool,
    anonymous_id: OnceCell<String>,
    endpoint: Option<String>,
    debug: bool,
    custom_track: Option<Arc<dyn Fn(TelemetryEvent) + Send + Sync>>,
    base_url: Option<String>,
}

impl Telemetry {
    /// Create a new Telemetry instance from auth options and optional context.
    ///
    /// Mirrors TS `createTelemetry(options, context?)`.
    pub async fn new(
        options: &BetterAuthOptions,
        context: Option<TelemetryContext>,
    ) -> Self {
        let debug = std::env::var("BETTER_AUTH_TELEMETRY_DEBUG")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

        let endpoint = std::env::var("BETTER_AUTH_TELEMETRY_ENDPOINT").ok();

        let custom_track = context.as_ref().and_then(|c| c.custom_track.clone());

        // Determine if telemetry is enabled
        let env_enabled = std::env::var("BETTER_AUTH_TELEMETRY")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

        let is_test = cfg!(test)
            || std::env::var("RUST_TEST")
                .map(|v| v == "1")
                .unwrap_or(false);

        let skip_test_check = context
            .as_ref()
            .map(|c| c.skip_test_check)
            .unwrap_or(false);

        let enabled = env_enabled && (skip_test_check || !is_test);

        if !enabled && endpoint.is_none() && custom_track.is_none() {
            return Self {
                enabled: false,
                anonymous_id: OnceCell::new(),
                endpoint: None,
                debug,
                custom_track: None,
                base_url: options.base_url.clone(),
            };
        }

        let telemetry = Self {
            enabled,
            anonymous_id: OnceCell::new(),
            endpoint,
            debug,
            custom_track,
            base_url: options.base_url.clone(),
        };

        if enabled {
            let anonymous_id = get_project_id(options.base_url.as_deref()).await;
            let _ = telemetry.anonymous_id.set(anonymous_id.clone());

            // Fire init event
            let payload = serde_json::json!({
                "config": detect_auth_config(options, context.as_ref()),
                "runtime": detect_runtime(),
                "database": detect_database(),
                "framework": detect_framework(),
                "environment": detect_environment(),
                "systemInfo": detect_system_info(),
                "packageManager": detect_package_manager(),
            });

            let init_event = TelemetryEvent {
                event_type: "init".to_string(),
                payload,
                anonymous_id: Some(anonymous_id),
            };

            // Fire-and-forget init event
            let _ = telemetry.track(&init_event).await;
        }

        telemetry
    }

    /// Publish a telemetry event.
    ///
    /// Mirrors TS `telemetry.publish(event)`.
    pub async fn publish(&self, event: TelemetryEvent) {
        if !self.enabled {
            return;
        }

        let anonymous_id = match self.anonymous_id.get() {
            Some(id) => id.clone(),
            None => {
                let id = get_project_id(self.base_url.as_deref()).await;
                id
            }
        };

        let full_event = TelemetryEvent {
            event_type: event.event_type,
            payload: event.payload,
            anonymous_id: Some(anonymous_id),
        };

        let _ = self.track(&full_event).await;
    }

    /// Internal track function — sends event to endpoint or custom handler.
    async fn track(&self, event: &TelemetryEvent) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(ref custom_track) = self.custom_track {
            custom_track(event.clone());
            return Ok(());
        }

        if let Some(ref endpoint) = self.endpoint {
            if self.debug {
                tracing::info!(
                    event_type = %event.event_type,
                    payload = %serde_json::to_string_pretty(&event.payload).unwrap_or_default(),
                    "telemetry event"
                );
            } else {
                let body = serde_json::json!({
                    "type": event.event_type,
                    "payload": event.payload,
                    "anonymousId": event.anonymous_id,
                });

                let client = reqwest::Client::new();
                client
                    .post(endpoint)
                    .json(&body)
                    .send()
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, "telemetry send failed");
                        e
                    })?;
            }
        }

        Ok(())
    }

    /// Returns a no-op telemetry instance.
    pub fn noop() -> Self {
        Self {
            enabled: false,
            anonymous_id: OnceCell::new(),
            endpoint: None,
            debug: false,
            custom_track: None,
            base_url: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_noop_telemetry() {
        let telemetry = Telemetry::noop();
        assert!(!telemetry.enabled);

        // Should not panic
        telemetry
            .publish(TelemetryEvent {
                event_type: "test".to_string(),
                payload: serde_json::json!({}),
                anonymous_id: None,
            })
            .await;
    }

    #[tokio::test]
    async fn test_telemetry_disabled_by_default() {
        let options = BetterAuthOptions::default();
        let telemetry = Telemetry::new(&options, None).await;
        assert!(!telemetry.enabled);
    }

    #[test]
    fn test_detection_info() {
        let info = DetectionInfo {
            name: "rust".to_string(),
            version: Some("1.85.0".to_string()),
        };
        assert_eq!(info.name, "rust");
        assert_eq!(info.version, Some("1.85.0".to_string()));
    }
}
