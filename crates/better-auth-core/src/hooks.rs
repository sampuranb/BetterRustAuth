// Async hooks — maps to packages/better-auth/src/types/context.ts hooks and callbacks.
//
// Provides a system for registering async lifecycle callbacks that fire
// on authentication events. These map to the TypeScript event hooks like
// `beforeEmailVerification`, `afterEmailVerification`, `onSession`, etc.

use async_trait::async_trait;
use serde_json::Value;
use std::sync::Arc;

/// The kind of auth event that triggered a hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HookEvent {
    /// Before verifying an email.
    BeforeEmailVerification,
    /// After verifying an email.
    AfterEmailVerification,
    /// Before creating a session.
    BeforeSessionCreate,
    /// After creating a session.
    AfterSessionCreate,
    /// Before signing up a user.
    BeforeSignUp,
    /// After signing up a user.
    AfterSignUp,
    /// Before signing in a user.
    BeforeSignIn,
    /// After signing in a user.
    AfterSignIn,
    /// Before signing out a user.
    BeforeSignOut,
    /// After signing out a user.
    AfterSignOut,
    /// Before changing email.
    BeforeEmailChange,
    /// After changing email.
    AfterEmailChange,
    /// Before changing password.
    BeforePasswordChange,
    /// After changing password.
    AfterPasswordChange,
}

impl HookEvent {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::BeforeEmailVerification => "before_email_verification",
            Self::AfterEmailVerification => "after_email_verification",
            Self::BeforeSessionCreate => "before_session_create",
            Self::AfterSessionCreate => "after_session_create",
            Self::BeforeSignUp => "before_sign_up",
            Self::AfterSignUp => "after_sign_up",
            Self::BeforeSignIn => "before_sign_in",
            Self::AfterSignIn => "after_sign_in",
            Self::BeforeSignOut => "before_sign_out",
            Self::AfterSignOut => "after_sign_out",
            Self::BeforeEmailChange => "before_email_change",
            Self::AfterEmailChange => "after_email_change",
            Self::BeforePasswordChange => "before_password_change",
            Self::AfterPasswordChange => "after_password_change",
        }
    }
}

/// An async hook that can be registered around auth events.
///
/// `before` hooks return a `HookResult` that can modify the data or cancel the operation.
/// `after` hooks are fire-and-forget.
#[async_trait]
pub trait AsyncHook: Send + Sync {
    /// Called when an event fires. `data` is event-specific JSON payload.
    ///
    /// For "before" events, return `HookResult::Cancel` to abort the operation or
    /// `HookResult::Continue(modified_data)` to proceed (with optional modifications).
    ///
    /// For "after" events, the return value is ignored.
    async fn on_event(&self, event: HookEvent, data: &Value) -> HookResult;
}

/// The result of a hook execution.
#[derive(Debug, Clone)]
pub enum HookResult {
    /// Continue the operation with optionally modified data.
    Continue(Option<Value>),
    /// Cancel the operation.
    Cancel(Option<String>),
}

impl HookResult {
    pub fn ok() -> Self {
        Self::Continue(None)
    }

    pub fn with_data(data: Value) -> Self {
        Self::Continue(Some(data))
    }

    pub fn cancel(reason: impl Into<String>) -> Self {
        Self::Cancel(Some(reason.into()))
    }

    pub fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancel(_))
    }
}

/// Registry of async hooks.
///
/// Supports registering multiple hooks per event and running them in order.
#[derive(Clone, Default)]
pub struct AsyncHookRegistry {
    hooks: Vec<(HookEvent, Arc<dyn AsyncHook>)>,
}

impl std::fmt::Debug for AsyncHookRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AsyncHookRegistry")
            .field("hook_count", &self.hooks.len())
            .finish()
    }
}

impl AsyncHookRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a hook for a specific event.
    pub fn register(&mut self, event: HookEvent, hook: Arc<dyn AsyncHook>) {
        self.hooks.push((event, hook));
    }

    /// Run all hooks for a "before" event in registration order.
    ///
    /// Returns `HookResult::Cancel` if any hook cancels the operation.
    /// Returns `HookResult::Continue` with the (potentially modified) data.
    pub async fn run_before(&self, event: HookEvent, data: &Value) -> HookResult {
        let mut current_data = data.clone();
        for (hook_event, hook) in &self.hooks {
            if *hook_event == event {
                let result = hook.on_event(event, &current_data).await;
                match result {
                    HookResult::Continue(Some(modified)) => {
                        current_data = modified;
                    }
                    HookResult::Continue(None) => {}
                    HookResult::Cancel(reason) => {
                        return HookResult::Cancel(reason);
                    }
                }
            }
        }
        HookResult::Continue(Some(current_data))
    }

    /// Run all hooks for an "after" event (fire-and-forget, results ignored).
    pub async fn run_after(&self, event: HookEvent, data: &Value) {
        for (hook_event, hook) in &self.hooks {
            if *hook_event == event {
                let _ = hook.on_event(event, data).await;
            }
        }
    }

    /// Whether any hooks are registered.
    pub fn is_empty(&self) -> bool {
        self.hooks.is_empty()
    }

    /// Number of registered hooks.
    pub fn len(&self) -> usize {
        self.hooks.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestHook {
        result: HookResult,
    }

    impl TestHook {
        fn ok() -> Self {
            Self {
                result: HookResult::ok(),
            }
        }

        fn cancel() -> Self {
            Self {
                result: HookResult::cancel("cancelled by test"),
            }
        }

        fn modify(data: Value) -> Self {
            Self {
                result: HookResult::with_data(data),
            }
        }
    }

    #[async_trait]
    impl AsyncHook for TestHook {
        async fn on_event(&self, _event: HookEvent, _data: &Value) -> HookResult {
            self.result.clone()
        }
    }

    #[tokio::test]
    async fn test_hook_result_ok() {
        let result = HookResult::ok();
        assert!(!result.is_cancelled());
    }

    #[tokio::test]
    async fn test_hook_result_cancel() {
        let result = HookResult::cancel("reason");
        assert!(result.is_cancelled());
    }

    #[tokio::test]
    async fn test_empty_registry_continue() {
        let registry = AsyncHookRegistry::new();
        let result = registry
            .run_before(HookEvent::BeforeSignIn, &serde_json::json!({}))
            .await;
        assert!(!result.is_cancelled());
    }

    #[tokio::test]
    async fn test_hook_ok_continues() {
        let mut registry = AsyncHookRegistry::new();
        registry.register(HookEvent::BeforeSignIn, Arc::new(TestHook::ok()));
        let result = registry
            .run_before(HookEvent::BeforeSignIn, &serde_json::json!({"user": "test"}))
            .await;
        assert!(!result.is_cancelled());
    }

    #[tokio::test]
    async fn test_hook_cancel_stops() {
        let mut registry = AsyncHookRegistry::new();
        registry.register(HookEvent::BeforeSignIn, Arc::new(TestHook::cancel()));
        let result = registry
            .run_before(HookEvent::BeforeSignIn, &serde_json::json!({}))
            .await;
        assert!(result.is_cancelled());
    }

    #[tokio::test]
    async fn test_hook_modifies_data() {
        let mut registry = AsyncHookRegistry::new();
        let modified = serde_json::json!({"modified": true});
        registry.register(
            HookEvent::BeforeSignUp,
            Arc::new(TestHook::modify(modified.clone())),
        );
        let result = registry
            .run_before(HookEvent::BeforeSignUp, &serde_json::json!({}))
            .await;
        match result {
            HookResult::Continue(Some(data)) => {
                assert_eq!(data, modified);
            }
            _ => panic!("Expected Continue with modified data"),
        }
    }

    #[tokio::test]
    async fn test_multiple_hooks_chain() {
        let mut registry = AsyncHookRegistry::new();
        // First hook modifies data
        registry.register(
            HookEvent::BeforeSignUp,
            Arc::new(TestHook::modify(serde_json::json!({"step": 1}))),
        );
        // Second hook passes through
        registry.register(HookEvent::BeforeSignUp, Arc::new(TestHook::ok()));

        let result = registry
            .run_before(HookEvent::BeforeSignUp, &serde_json::json!({}))
            .await;
        match result {
            HookResult::Continue(Some(data)) => {
                assert_eq!(data["step"], 1);
            }
            _ => panic!("Expected Continue"),
        }
    }

    #[tokio::test]
    async fn test_cancel_short_circuits() {
        let mut registry = AsyncHookRegistry::new();
        registry.register(HookEvent::BeforeSignIn, Arc::new(TestHook::cancel()));
        // This hook should never run
        registry.register(
            HookEvent::BeforeSignIn,
            Arc::new(TestHook::modify(serde_json::json!({"should_not": "reach"}))),
        );

        let result = registry
            .run_before(HookEvent::BeforeSignIn, &serde_json::json!({}))
            .await;
        assert!(result.is_cancelled());
    }

    #[tokio::test]
    async fn test_wrong_event_ignored() {
        let mut registry = AsyncHookRegistry::new();
        registry.register(HookEvent::BeforeSignIn, Arc::new(TestHook::cancel()));
        // Different event — should not cancel
        let result = registry
            .run_before(HookEvent::BeforeSignUp, &serde_json::json!({}))
            .await;
        assert!(!result.is_cancelled());
    }

    #[tokio::test]
    async fn test_after_hooks_run() {
        let mut registry = AsyncHookRegistry::new();
        registry.register(HookEvent::AfterSignIn, Arc::new(TestHook::ok()));
        // After hooks are fire-and-forget, just make sure they don't panic
        registry
            .run_after(HookEvent::AfterSignIn, &serde_json::json!({"user_id": "u1"}))
            .await;
    }

    #[test]
    fn test_registry_len() {
        let mut registry = AsyncHookRegistry::new();
        assert!(registry.is_empty());
        assert_eq!(registry.len(), 0);
        registry.register(HookEvent::BeforeSignIn, Arc::new(TestHook::ok()));
        assert!(!registry.is_empty());
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn test_hook_event_as_str() {
        assert_eq!(HookEvent::BeforeEmailVerification.as_str(), "before_email_verification");
        assert_eq!(HookEvent::AfterSignOut.as_str(), "after_sign_out");
    }
}
