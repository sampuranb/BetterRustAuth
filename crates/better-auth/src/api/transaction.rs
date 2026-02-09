// Transaction context — maps to packages/core/src/context/transaction.ts
//
// Provides database transaction scoping and post-commit hook management.
// In TS, this uses AsyncLocalStorage to swap the adapter during a transaction.
// In Rust, we use an explicit TransactionContext passed through the call chain.

use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::Mutex;

/// A boxed future type for post-commit hooks.
type BoxFuture = Pin<Box<dyn std::future::Future<Output = ()> + Send>>;

/// Context for managing database transactions within a request.
///
/// Maps to the TS `HookContext` which carries:
/// - `adapter`: The transactional adapter (or fallback)
/// - `pendingHooks`: Hooks queued to execute after transaction commit
///
/// In Rust, the transaction adapter is typically obtained from
/// the database driver (e.g., sqlx transaction) and the caller
/// passes it through.
#[derive(Clone)]
pub struct TransactionContext {
    /// Post-commit hooks queued during the transaction.
    pending_hooks: Arc<Mutex<Vec<Box<dyn FnOnce() -> BoxFuture + Send + Sync>>>>,
}

impl TransactionContext {
    /// Create a new transaction context.
    pub fn new() -> Self {
        Self {
            pending_hooks: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Queue a hook to execute after the transaction commits.
    ///
    /// Maps to TS `queueAfterTransactionHook`.
    pub async fn queue_hook<F, Fut>(&self, hook: F)
    where
        F: FnOnce() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let mut hooks = self.pending_hooks.lock().await;
        hooks.push(Box::new(move || Box::pin(hook()) as BoxFuture));
    }

    /// Execute all pending hooks (typically called after commit).
    ///
    /// Clears the hook queue after execution.
    pub async fn execute_pending_hooks(&self) {
        let hooks: Vec<Box<dyn FnOnce() -> BoxFuture + Send + Sync>> = {
            let mut guard = self.pending_hooks.lock().await;
            std::mem::take(&mut *guard)
        };

        for hook in hooks {
            hook().await;
        }
    }

    /// Returns the number of pending hooks.
    pub async fn pending_count(&self) -> usize {
        self.pending_hooks.lock().await.len()
    }
}

impl Default for TransactionContext {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for TransactionContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransactionContext")
            .field("pending_hooks", &"[...]")
            .finish()
    }
}

/// Run a function within a transaction context, executing pending hooks
/// afterward regardless of success or failure.
///
/// Maps to TS `runWithAdapter` / `runWithTransaction`.
///
/// # Arguments
/// * `f` - The function to execute within the transaction context
///
/// # Returns
/// The result of the function, after all pending hooks have been executed.
pub async fn run_with_transaction<F, Fut, R>(
    f: F,
) -> R
where
    F: FnOnce(TransactionContext) -> Fut,
    Fut: std::future::Future<Output = R>,
{
    let tx_ctx = TransactionContext::new();
    let result = f(tx_ctx.clone()).await;
    tx_ctx.execute_pending_hooks().await;
    result
}

/// Queue a hook for after the current transaction commits.
///
/// If not in a transaction, the hook executes immediately.
///
/// Maps to TS `queueAfterTransactionHook`.
pub async fn queue_after_transaction_hook<F, Fut>(
    tx_ctx: Option<&TransactionContext>,
    hook: F,
)
where
    F: FnOnce() -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    match tx_ctx {
        Some(ctx) => {
            ctx.queue_hook(hook).await;
        }
        None => {
            // No transaction context — execute immediately
            hook().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[tokio::test]
    async fn test_transaction_context_hooks() {
        let counter = Arc::new(AtomicU32::new(0));
        let tx_ctx = TransactionContext::new();

        // Queue some hooks
        let c1 = counter.clone();
        tx_ctx.queue_hook(move || async move {
            c1.fetch_add(1, Ordering::SeqCst);
        }).await;

        let c2 = counter.clone();
        tx_ctx.queue_hook(move || async move {
            c2.fetch_add(10, Ordering::SeqCst);
        }).await;

        assert_eq!(tx_ctx.pending_count().await, 2);
        assert_eq!(counter.load(Ordering::SeqCst), 0);

        // Execute hooks
        tx_ctx.execute_pending_hooks().await;
        assert_eq!(counter.load(Ordering::SeqCst), 11);
        assert_eq!(tx_ctx.pending_count().await, 0);
    }

    #[tokio::test]
    async fn test_run_with_transaction() {
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();

        let result = run_with_transaction(|tx_ctx| async move {
            let c = c.clone();
            tx_ctx.queue_hook(move || async move {
                c.fetch_add(1, Ordering::SeqCst);
            }).await;
            42
        }).await;

        assert_eq!(result, 42);
        // Hook should have executed after the function
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_queue_after_transaction_hook_with_context() {
        let counter = Arc::new(AtomicU32::new(0));
        let tx_ctx = TransactionContext::new();

        let c = counter.clone();
        queue_after_transaction_hook(Some(&tx_ctx), move || async move {
            c.fetch_add(1, Ordering::SeqCst);
        }).await;

        // Not executed yet (queued)
        assert_eq!(counter.load(Ordering::SeqCst), 0);

        tx_ctx.execute_pending_hooks().await;
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_queue_after_transaction_hook_without_context() {
        let counter = Arc::new(AtomicU32::new(0));
        let c = counter.clone();

        queue_after_transaction_hook(None, move || async move {
            c.fetch_add(1, Ordering::SeqCst);
        }).await;

        // Without context, executes immediately
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }
}
