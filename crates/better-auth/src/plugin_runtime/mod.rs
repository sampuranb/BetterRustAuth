// Plugin runtime — collects, initializes, and wires plugins at startup.
//
// Maps to: packages/better-auth/src/context/helpers.ts runPluginInit +
//          packages/core/src/api/index.ts endpoint registration +
//          packages/better-auth/src/db/schema.ts mergeSchema
//
// Sub-modules:
// - registry: PluginRegistry collects all enabled plugins
// - endpoint_router: Route collection and dispatch
// - schema_merger: Merges plugin schema into base schema

pub mod registry;
pub mod endpoint_router;
pub mod schema_merger;

pub use registry::PluginRegistry;
