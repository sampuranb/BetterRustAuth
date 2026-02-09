// Database hooks — maps to packages/better-auth/src/db/with-hooks.ts
//
// CRUD lifecycle hook system allowing plugins and users to intercept
// every database operation with before/after callbacks.

use async_trait::async_trait;
use serde_json::Value;
use std::sync::Arc;

// ─── Hook Results ───────────────────────────────────────────────

/// Result from a before-hook.
///
/// - `Continue(None)` → proceed with original data
/// - `Continue(Some(data))` → proceed with modified data  
/// - `Cancel` → abort the operation (returns None to caller)
pub enum BeforeHookResult {
    /// Continue the operation, optionally with modified data.
    Continue(Option<Value>),
    /// Cancel the operation entirely.
    Cancel,
}

impl BeforeHookResult {
    /// Continue with original data.
    pub fn ok() -> Self {
        Self::Continue(None)
    }

    /// Continue with modified data.
    pub fn with_data(data: Value) -> Self {
        Self::Continue(Some(data))
    }

    /// Cancel the operation.
    pub fn cancel() -> Self {
        Self::Cancel
    }
}

// ─── Model Names ────────────────────────────────────────────────

/// The core model names that hooks can be registered for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ModelName {
    User,
    Session,
    Account,
    Verification,
}

impl ModelName {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Session => "session",
            Self::Account => "account",
            Self::Verification => "verification",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "user" => Some(Self::User),
            "session" => Some(Self::Session),
            "account" => Some(Self::Account),
            "verification" => Some(Self::Verification),
            _ => None,
        }
    }
}

// ─── Hook Trait ─────────────────────────────────────────────────

/// Database hooks for intercepting CRUD operations.
///
/// Implement this trait to add custom behavior before/after database
/// operations. Multiple hooks can be registered and are executed in order.
///
/// Maps to TypeScript `databaseHooks` configuration option.
#[async_trait]
pub trait DatabaseHooks: Send + Sync {
    /// Called before a record is created.
    /// Return `BeforeHookResult::Cancel` to prevent creation.
    /// Return `BeforeHookResult::with_data(modified)` to change the data being created.
    async fn before_create(&self, _model: ModelName, _data: &Value) -> BeforeHookResult {
        BeforeHookResult::ok()
    }

    /// Called after a record is created.
    async fn after_create(&self, _model: ModelName, _data: &Value) {}

    /// Called before a record is updated.
    /// Return `BeforeHookResult::Cancel` to prevent the update.
    /// Return `BeforeHookResult::with_data(modified)` to change the update data.
    async fn before_update(&self, _model: ModelName, _data: &Value) -> BeforeHookResult {
        BeforeHookResult::ok()
    }

    /// Called after a record is updated.
    async fn after_update(&self, _model: ModelName, _data: &Value) {}

    /// Called before a record is deleted.
    /// Return `BeforeHookResult::Cancel` to prevent deletion.
    async fn before_delete(&self, _model: ModelName, _data: &Value) -> BeforeHookResult {
        BeforeHookResult::ok()
    }

    /// Called after a record is deleted.
    async fn after_delete(&self, _model: ModelName, _data: &Value) {}
}

// ─── Hook Registry ──────────────────────────────────────────────

/// A collection of database hooks to execute.
#[derive(Default, Clone)]
pub struct HookRegistry {
    hooks: Vec<Arc<dyn DatabaseHooks>>,
}

impl HookRegistry {
    /// Create a new empty hook registry.
    pub fn new() -> Self {
        Self { hooks: Vec::new() }
    }

    /// Add a hook to the registry.
    pub fn add(&mut self, hook: Arc<dyn DatabaseHooks>) {
        self.hooks.push(hook);
    }

    /// Whether any hooks are registered.
    pub fn is_empty(&self) -> bool {
        self.hooks.is_empty()
    }

    /// Run all before-create hooks. Returns modified data or None if cancelled.
    pub async fn run_before_create(&self, model: ModelName, data: Value) -> Option<Value> {
        let mut current = data;
        for hook in &self.hooks {
            match hook.before_create(model, &current).await {
                BeforeHookResult::Cancel => return None,
                BeforeHookResult::Continue(Some(modified)) => {
                    // Merge modified data into current
                    if let (Some(base), Some(patch)) = (current.as_object_mut(), modified.as_object()) {
                        for (k, v) in patch {
                            base.insert(k.clone(), v.clone());
                        }
                    } else {
                        current = modified;
                    }
                }
                BeforeHookResult::Continue(None) => {}
            }
        }
        Some(current)
    }

    /// Run all after-create hooks.
    pub async fn run_after_create(&self, model: ModelName, data: &Value) {
        for hook in &self.hooks {
            hook.after_create(model, data).await;
        }
    }

    /// Run all before-update hooks. Returns modified data or None if cancelled.
    pub async fn run_before_update(&self, model: ModelName, data: Value) -> Option<Value> {
        let mut current = data;
        for hook in &self.hooks {
            match hook.before_update(model, &current).await {
                BeforeHookResult::Cancel => return None,
                BeforeHookResult::Continue(Some(modified)) => {
                    if let (Some(base), Some(patch)) = (current.as_object_mut(), modified.as_object()) {
                        for (k, v) in patch {
                            base.insert(k.clone(), v.clone());
                        }
                    } else {
                        current = modified;
                    }
                }
                BeforeHookResult::Continue(None) => {}
            }
        }
        Some(current)
    }

    /// Run all after-update hooks.
    pub async fn run_after_update(&self, model: ModelName, data: &Value) {
        for hook in &self.hooks {
            hook.after_update(model, data).await;
        }
    }

    /// Run all before-delete hooks. Returns false if cancelled.
    pub async fn run_before_delete(&self, model: ModelName, data: &Value) -> bool {
        for hook in &self.hooks {
            match hook.before_delete(model, data).await {
                BeforeHookResult::Cancel => return false,
                _ => {}
            }
        }
        true
    }

    /// Run all after-delete hooks.
    pub async fn run_after_delete(&self, model: ModelName, data: &Value) {
        for hook in &self.hooks {
            hook.after_delete(model, data).await;
        }
    }
}

// ─── WithHooks CRUD Wrappers ────────────────────────────────────

impl std::fmt::Debug for HookRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HookRegistry")
            .field("hook_count", &self.hooks.len())
            .finish()
    }
}

/// A custom function that can replace or augment the main adapter operation.
///
/// Matches the TS `customCreateFn` / `customUpdateFn` pattern.
pub struct CustomFn {
    /// The custom function to execute.
    pub func: Box<dyn Fn(Value) -> std::pin::Pin<Box<dyn std::future::Future<Output = Option<Value>> + Send>> + Send + Sync>,
    /// Whether to also execute the main adapter operation after the custom function.
    pub execute_main_fn: bool,
}

/// CRUD wrapper that integrates database hooks with an adapter.
///
/// Maps to the TS `getWithHooks()` function which returns
/// `{createWithHooks, updateWithHooks, updateManyWithHooks, deleteWithHooks, deleteManyWithHooks}`.
pub struct WithHooks {
    adapter: Arc<dyn better_auth_core::db::adapter::Adapter>,
    hooks: HookRegistry,
}

impl WithHooks {
    /// Create a new WithHooks wrapper.
    pub fn new(
        adapter: Arc<dyn better_auth_core::db::adapter::Adapter>,
        hooks: HookRegistry,
    ) -> Self {
        Self { adapter, hooks }
    }

    /// Create a record with before/after hooks.
    ///
    /// 1. Run before_create hooks (may modify data or cancel)
    /// 2. Execute adapter.create (or custom_fn)
    /// 3. Run after_create hooks
    pub async fn create_with_hooks(
        &self,
        data: Value,
        model: ModelName,
        custom_fn: Option<CustomFn>,
    ) -> Option<Value> {
        // Run before hooks
        let data = match self.hooks.run_before_create(model, data).await {
            Some(d) => d,
            None => return None, // Cancelled
        };

        let result = if let Some(custom) = custom_fn {
            let custom_result = (custom.func)(data.clone()).await;

            if custom.execute_main_fn {
                // Run the main adapter too
                match self.adapter.create(model.as_str(), data, None).await {
                    Ok(v) => Some(v),
                    Err(_) => custom_result,
                }
            } else {
                custom_result
            }
        } else {
            match self.adapter.create(model.as_str(), data, None).await {
                Ok(v) => Some(v),
                Err(_) => None,
            }
        };

        // Run after hooks
        if let Some(ref created) = result {
            self.hooks.run_after_create(model, created).await;
        }

        result
    }

    /// Update a record with before/after hooks.
    ///
    /// 1. Run before_update hooks (may modify data or cancel)
    /// 2. Execute adapter.update
    /// 3. Run after_update hooks
    pub async fn update_with_hooks(
        &self,
        wheres: &[better_auth_core::db::adapter::WhereClause],
        data: Value,
        model: ModelName,
    ) -> Option<Value> {
        // Run before hooks
        let data = match self.hooks.run_before_update(model, data).await {
            Some(d) => d,
            None => return None,
        };

        let result = match self.adapter.update(model.as_str(), wheres, data).await {
            Ok(v) => v,
            Err(_) => None,
        };

        // Run after hooks
        if let Some(ref updated) = result {
            self.hooks.run_after_update(model, updated).await;
        }

        result
    }

    /// Update many records with before/after hooks.
    ///
    /// For bulk updates, hooks are called once with the update data
    /// (not per-record, since the adapter returns a count not individual records).
    pub async fn update_many_with_hooks(
        &self,
        wheres: &[better_auth_core::db::adapter::WhereClause],
        data: Value,
        model: ModelName,
    ) -> Option<Value> {
        // Run before hooks with the update data
        let data = match self.hooks.run_before_update(model, data).await {
            Some(d) => d,
            None => return None,
        };

        // For update_many, we use the regular update + hooks
        let result = match self.adapter.update(model.as_str(), wheres, data.clone()).await {
            Ok(v) => v,
            Err(_) => None,
        };

        if let Some(ref updated) = result {
            self.hooks.run_after_update(model, updated).await;
        }

        result
    }

    /// Delete a record with before/after hooks.
    ///
    /// 1. Look up the record first (so we can pass it to hooks)
    /// 2. Run before_delete hooks (may cancel)
    /// 3. Execute adapter.delete
    /// 4. Run after_delete hooks
    pub async fn delete_with_hooks(
        &self,
        wheres: &[better_auth_core::db::adapter::WhereClause],
        model: ModelName,
    ) -> bool {
        // First look up the record for hook context
        let existing = match self.adapter.find_one(model.as_str(), wheres).await {
            Ok(Some(v)) => v,
            _ => return false,
        };

        // Run before hooks
        if !self.hooks.run_before_delete(model, &existing).await {
            return false; // Cancelled
        }

        // Execute delete
        match self.adapter.delete(model.as_str(), wheres).await {
            Ok(_) => {
                self.hooks.run_after_delete(model, &existing).await;
                true
            }
            Err(_) => false,
        }
    }

    /// Delete many records with before/after hooks.
    ///
    /// Looks up matching records first, runs per-record before hooks (any cancel
    /// aborts the entire batch), then deletes all and runs per-record after hooks.
    pub async fn delete_many_with_hooks(
        &self,
        wheres: &[better_auth_core::db::adapter::WhereClause],
        model: ModelName,
    ) -> i64 {
        // Look up all matching records
        let query = better_auth_core::db::adapter::FindManyQuery {
            where_clauses: wheres.to_vec(),
            ..Default::default()
        };
        let records = match self.adapter.find_many(model.as_str(), query).await {
            Ok(v) => v,
            Err(_) => return 0,
        };

        // Run before hooks for each record
        for record in &records {
            if !self.hooks.run_before_delete(model, record).await {
                return 0; // Cancelled
            }
        }

        // Execute batch delete
        let count = match self.adapter.delete_many(model.as_str(), wheres).await {
            Ok(n) => n,
            Err(_) => return 0,
        };

        // Run after hooks for each record
        for record in &records {
            self.hooks.run_after_delete(model, record).await;
        }

        count
    }
}

impl std::fmt::Debug for WithHooks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WithHooks")
            .field("hooks", &self.hooks)
            .finish()
    }
}


// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    /// Test hook that tracks invocations.
    struct TrackingHook {
        before_create_called: AtomicBool,
        after_create_called: AtomicBool,
        before_update_called: AtomicBool,
        after_update_called: AtomicBool,
        before_delete_called: AtomicBool,
        after_delete_called: AtomicBool,
    }

    impl TrackingHook {
        fn new() -> Self {
            Self {
                before_create_called: AtomicBool::new(false),
                after_create_called: AtomicBool::new(false),
                before_update_called: AtomicBool::new(false),
                after_update_called: AtomicBool::new(false),
                before_delete_called: AtomicBool::new(false),
                after_delete_called: AtomicBool::new(false),
            }
        }
    }

    #[async_trait]
    impl DatabaseHooks for TrackingHook {
        async fn before_create(&self, _model: ModelName, _data: &Value) -> BeforeHookResult {
            self.before_create_called.store(true, Ordering::SeqCst);
            BeforeHookResult::ok()
        }

        async fn after_create(&self, _model: ModelName, _data: &Value) {
            self.after_create_called.store(true, Ordering::SeqCst);
        }

        async fn before_update(&self, _model: ModelName, _data: &Value) -> BeforeHookResult {
            self.before_update_called.store(true, Ordering::SeqCst);
            BeforeHookResult::ok()
        }

        async fn after_update(&self, _model: ModelName, _data: &Value) {
            self.after_update_called.store(true, Ordering::SeqCst);
        }

        async fn before_delete(&self, _model: ModelName, _data: &Value) -> BeforeHookResult {
            self.before_delete_called.store(true, Ordering::SeqCst);
            BeforeHookResult::ok()
        }

        async fn after_delete(&self, _model: ModelName, _data: &Value) {
            self.after_delete_called.store(true, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn test_before_after_create_hooks_invoked() {
        let hook = Arc::new(TrackingHook::new());
        let mut registry = HookRegistry::new();
        registry.add(hook.clone());

        let data = serde_json::json!({"name": "test"});
        let result = registry.run_before_create(ModelName::User, data).await;
        assert!(result.is_some());
        assert!(hook.before_create_called.load(Ordering::SeqCst));

        registry.run_after_create(ModelName::User, &serde_json::json!({})).await;
        assert!(hook.after_create_called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_before_hook_can_cancel() {
        struct CancelHook;

        #[async_trait]
        impl DatabaseHooks for CancelHook {
            async fn before_create(&self, _model: ModelName, _data: &Value) -> BeforeHookResult {
                BeforeHookResult::cancel()
            }
        }

        let mut registry = HookRegistry::new();
        registry.add(Arc::new(CancelHook));

        let data = serde_json::json!({"name": "test"});
        let result = registry.run_before_create(ModelName::User, data).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_before_hook_can_modify_data() {
        struct ModifyHook;

        #[async_trait]
        impl DatabaseHooks for ModifyHook {
            async fn before_create(&self, _model: ModelName, _data: &Value) -> BeforeHookResult {
                BeforeHookResult::with_data(serde_json::json!({"extra": true}))
            }
        }

        let mut registry = HookRegistry::new();
        registry.add(Arc::new(ModifyHook));

        let data = serde_json::json!({"name": "test"});
        let result = registry.run_before_create(ModelName::User, data).await;
        let result = result.unwrap();
        assert_eq!(result["name"], "test");
        assert_eq!(result["extra"], true);
    }

    #[tokio::test]
    async fn test_multiple_hooks_chain() {
        let call_order = Arc::new(AtomicU32::new(0));

        struct FirstHook(Arc<AtomicU32>);
        struct SecondHook(Arc<AtomicU32>);

        #[async_trait]
        impl DatabaseHooks for FirstHook {
            async fn before_create(&self, _model: ModelName, _data: &Value) -> BeforeHookResult {
                self.0.fetch_add(1, Ordering::SeqCst);
                BeforeHookResult::with_data(serde_json::json!({"step": 1}))
            }
        }

        #[async_trait]
        impl DatabaseHooks for SecondHook {
            async fn before_create(&self, _model: ModelName, data: &Value) -> BeforeHookResult {
                assert_eq!(data["step"], 1);
                self.0.fetch_add(1, Ordering::SeqCst);
                BeforeHookResult::with_data(serde_json::json!({"step": 2}))
            }
        }

        let mut registry = HookRegistry::new();
        registry.add(Arc::new(FirstHook(call_order.clone())));
        registry.add(Arc::new(SecondHook(call_order.clone())));

        let data = serde_json::json!({"name": "test"});
        let result = registry.run_before_create(ModelName::User, data).await;
        let result = result.unwrap();
        assert_eq!(result["step"], 2);
        assert_eq!(call_order.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_delete_hooks() {
        let hook = Arc::new(TrackingHook::new());
        let mut registry = HookRegistry::new();
        registry.add(hook.clone());

        let data = serde_json::json!({"id": "123"});
        let can_proceed = registry.run_before_delete(ModelName::Session, &data).await;
        assert!(can_proceed);
        assert!(hook.before_delete_called.load(Ordering::SeqCst));

        registry.run_after_delete(ModelName::Session, &data).await;
        assert!(hook.after_delete_called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_model_name_conversion() {
        assert_eq!(ModelName::User.as_str(), "user");
        assert_eq!(ModelName::Session.as_str(), "session");
        assert_eq!(ModelName::Account.as_str(), "account");
        assert_eq!(ModelName::Verification.as_str(), "verification");
        assert_eq!(ModelName::from_str("user"), Some(ModelName::User));
        assert_eq!(ModelName::from_str("unknown"), None);
    }

    #[tokio::test]
    async fn test_empty_registry_passes_through() {
        let registry = HookRegistry::new();
        assert!(registry.is_empty());

        let data = serde_json::json!({"name": "test"});
        let result = registry.run_before_create(ModelName::User, data.clone()).await;
        assert_eq!(result, Some(data));
    }
}
