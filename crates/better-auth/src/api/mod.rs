// API framework — maps to packages/better-auth/src/api/
//
// This module provides the core API infrastructure:
// - Endpoint conflict detection
// - Endpoint collection and routing
// - Before/after hook execution pipeline
// - Request/response lifecycle (onRequest, onResponse, onError)
// - Request-scoped state management

pub mod endpoint_pipeline;
pub mod endpoint_conflicts;
pub mod request_state;
pub mod transaction;

// Re-exports for convenience
pub use endpoint_conflicts::check_endpoint_conflicts;
pub use endpoint_pipeline::{
    EndpointPipeline, HookEntry, InternalContext, run_before_hooks, run_after_hooks,
    get_hooks,
};
pub use request_state::{RequestState, RequestStateStore};
pub use transaction::{TransactionContext, run_with_transaction, queue_after_transaction_hook};
