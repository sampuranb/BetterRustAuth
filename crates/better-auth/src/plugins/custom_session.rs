// Custom Session plugin — enriches session responses with custom data.
//
// Maps to: packages/better-auth/src/plugins/custom-session/index.ts
//
// This plugin overrides the /get-session endpoint to run a user-supplied
// transformation function on the session data before returning it.
// It can optionally also mutate the list-device-sessions response.
//
// In Rust, the transformation is represented as an `Arc<dyn SessionTransformer>` 
// trait object instead of a closure (for Send + Sync safety).

use std::collections::HashMap;

use async_trait::async_trait;

use better_auth_core::plugin::{
    BetterAuthPlugin, HookOperation, HookTiming, HttpMethod, PluginEndpoint, PluginHook,
};

/// Custom session plugin options.
#[derive(Debug, Clone, Default)]
pub struct CustomSessionOptions {
    /// Whether to also mutate the list-device-sessions endpoint.
    pub should_mutate_list_device_sessions: bool,
}

/// Trait for custom session data transformation.
///
/// In TS this is a plain function `(session, ctx) => Promise<Returns>`.
/// In Rust we use a trait for `Send + Sync` safety.
///
/// Example:
/// ```rust,ignore
/// struct MySessionTransformer;
///
/// #[async_trait]
/// impl SessionTransformer for MySessionTransformer {
///     async fn transform(
///         &self,
///         session_data: &serde_json::Value,
///     ) -> Result<serde_json::Value, String> {
///         let mut data = session_data.clone();
///         data["customField"] = serde_json::json!("custom-value");
///         Ok(data)
///     }
/// }
/// ```
#[async_trait]
pub trait SessionTransformer: Send + Sync + std::fmt::Debug {
    /// Transform the session/user data before returning it to the client.
    ///
    /// The input is the raw `{ user, session }` JSON object.
    /// The output should be the enriched version to return.
    async fn transform(
        &self,
        session_data: &serde_json::Value,
    ) -> Result<serde_json::Value, String>;
}

/// Custom session plugin.
#[derive(Debug)]
pub struct CustomSessionPlugin {
    options: CustomSessionOptions,
    transformer: Option<std::sync::Arc<dyn SessionTransformer>>,
}

impl CustomSessionPlugin {
    pub fn new(options: CustomSessionOptions) -> Self {
        Self {
            options,
            transformer: None,
        }
    }

    /// Create a custom session plugin with a transformer function.
    pub fn with_transformer(
        options: CustomSessionOptions,
        transformer: std::sync::Arc<dyn SessionTransformer>,
    ) -> Self {
        Self {
            options,
            transformer: Some(transformer),
        }
    }

    /// Access the transformer (for handler integration).
    pub fn transformer(&self) -> Option<&dyn SessionTransformer> {
        self.transformer.as_deref()
    }

    /// Apply the transformer to session data.
    ///
    /// Returns the original data unchanged if no transformer is configured.
    pub async fn apply_transform(
        &self,
        session_data: &serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        match &self.transformer {
            Some(t) => t.transform(session_data).await,
            None => Ok(session_data.clone()),
        }
    }
}

impl Default for CustomSessionPlugin {
    fn default() -> Self {
        Self::new(CustomSessionOptions::default())
    }
}

#[async_trait]
impl BetterAuthPlugin for CustomSessionPlugin {
    fn id(&self) -> &str {
        "custom-session"
    }

    fn name(&self) -> &str {
        "Custom Session"
    }

    fn endpoints(&self) -> Vec<PluginEndpoint> {
        vec![PluginEndpoint {
            path: "/get-session".to_string(),
            method: HttpMethod::Get,
            require_auth: true,
            metadata: {
                let mut m = HashMap::new();
                m.insert("CUSTOM_SESSION".to_string(), serde_json::Value::Bool(true));
                m
            },
            handler: None,
        }]
    }

    fn hooks(&self) -> Vec<PluginHook> {
        if self.options.should_mutate_list_device_sessions {
            vec![PluginHook {
                model: "session".to_string(),
                timing: HookTiming::After,
                operation: HookOperation::Create,
            }]
        } else {
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_id() {
        let plugin = CustomSessionPlugin::default();
        assert_eq!(plugin.id(), "custom-session");
    }

    #[test]
    fn test_endpoints() {
        let plugin = CustomSessionPlugin::default();
        let endpoints = plugin.endpoints();
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].path, "/get-session");
        assert!(endpoints[0].require_auth);
    }

    #[test]
    fn test_no_hooks_by_default() {
        let plugin = CustomSessionPlugin::default();
        assert!(plugin.hooks().is_empty());
    }

    #[test]
    fn test_hooks_with_device_sessions() {
        let plugin = CustomSessionPlugin::new(CustomSessionOptions {
            should_mutate_list_device_sessions: true,
        });
        assert_eq!(plugin.hooks().len(), 1);
    }

    #[derive(Debug)]
    struct TestTransformer;

    #[async_trait]
    impl SessionTransformer for TestTransformer {
        async fn transform(
            &self,
            data: &serde_json::Value,
        ) -> Result<serde_json::Value, String> {
            let mut result = data.clone();
            result["custom"] = serde_json::json!("injected");
            Ok(result)
        }
    }

    #[tokio::test]
    async fn test_apply_transform() {
        let plugin = CustomSessionPlugin::with_transformer(
            CustomSessionOptions::default(),
            std::sync::Arc::new(TestTransformer),
        );

        let input = serde_json::json!({
            "user": { "id": "u1", "name": "Test" },
            "session": { "id": "s1" }
        });

        let result = plugin.apply_transform(&input).await.unwrap();
        assert_eq!(result["custom"], "injected");
        assert_eq!(result["user"]["id"], "u1");
    }

    #[tokio::test]
    async fn test_apply_transform_no_transformer() {
        let plugin = CustomSessionPlugin::default();
        let input = serde_json::json!({"key": "value"});
        let result = plugin.apply_transform(&input).await.unwrap();
        assert_eq!(result, input);
    }
}
