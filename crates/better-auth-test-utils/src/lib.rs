// better-auth-test-utils — mirrors packages/test-utils/src
//
// Provides adapter testing infrastructure:
// - `TestSuite` for creating batches of adapter tests
// - `TestAdapter` for running test suites against any adapter
// - Model generators for user, session, account, verification
// - Statistics tracking and reporting

pub mod test_adapter;
pub mod test_suite;

pub use test_adapter::{TestAdapter, TestAdapterConfig};
pub use test_suite::{TestSuite, TestSuiteConfig, TestSuiteStats};
