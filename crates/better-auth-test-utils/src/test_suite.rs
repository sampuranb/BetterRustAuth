// Test suite definition — mirrors packages/test-utils/src/adapter/create-test-suite.ts
//
// A `TestSuite` groups related tests and tracks statistics (migration count,
// migration time, test count, duration). Tests can optionally require
// migration before running.

use std::time::Instant;

/// Statistics for a completed test suite.
///
/// Maps to TS `TestSuiteStats`.
#[derive(Debug, Clone)]
pub struct TestSuiteStats {
    pub migration_count: usize,
    pub total_migration_time_ms: f64,
    pub test_count: usize,
    pub suite_start_time: Instant,
    pub suite_duration_ms: f64,
    pub suite_name: String,
    pub grouping_stats: Option<GroupingStats>,
}

/// Grouping statistics for test suites.
#[derive(Debug, Clone)]
pub struct GroupingStats {
    pub total_groups: usize,
    pub average_tests_per_group: f64,
    pub largest_group_size: usize,
    pub smallest_group_size: usize,
    pub groups_with_multiple_tests: usize,
    pub total_tests_in_groups: usize,
}

/// Configuration for a test suite.
pub struct TestSuiteConfig {
    /// Name of the test suite.
    pub name: String,
    /// Whether to always run migrations before tests.
    pub always_migrate: bool,
}

impl Default for TestSuiteConfig {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            always_migrate: false,
        }
    }
}

/// A test case entry.
pub struct TestEntry {
    /// Name of the test.
    pub name: String,
    /// The async test function.
    pub test_fn: Box<dyn Fn(&TestHelpers) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Box<dyn std::error::Error>>> + Send + '_>> + Send + Sync>,
    /// Whether this test requires migration.
    pub requires_migration: bool,
}

/// Helpers available to test functions.
pub struct TestHelpers {
    /// Logger for test output.
    pub log: TestLogger,
}

/// Simple test logger.
///
/// Maps to TS `Logger` type.
pub struct TestLogger {
    pub adapter_name: String,
}

impl TestLogger {
    pub fn new(adapter_name: &str) -> Self {
        Self {
            adapter_name: adapter_name.to_string(),
        }
    }

    pub fn info(&self, msg: &str) {
        tracing::info!("[{}] {}", self.adapter_name, msg);
    }

    pub fn success(&self, msg: &str) {
        tracing::info!("[{}] ✓ {}", self.adapter_name, msg);
    }

    pub fn warn(&self, msg: &str) {
        tracing::warn!("[{}] {}", self.adapter_name, msg);
    }

    pub fn error(&self, msg: &str) {
        tracing::error!("[{}] {}", self.adapter_name, msg);
    }

    pub fn debug(&self, msg: &str) {
        tracing::debug!("[{}] {}", self.adapter_name, msg);
    }
}

/// A test suite that groups related adapter tests.
///
/// Maps to TS `createTestSuite(suiteName, config, tests)`.
pub struct TestSuite {
    pub config: TestSuiteConfig,
    pub tests: Vec<TestEntry>,
    pub stats: TestSuiteStats,
}

impl TestSuite {
    /// Create a new test suite.
    pub fn new(name: &str, always_migrate: bool) -> Self {
        let config = TestSuiteConfig {
            name: name.to_string(),
            always_migrate,
        };

        let stats = TestSuiteStats {
            migration_count: 0,
            total_migration_time_ms: 0.0,
            test_count: 0,
            suite_start_time: Instant::now(),
            suite_duration_ms: 0.0,
            suite_name: name.to_string(),
            grouping_stats: None,
        };

        Self {
            config,
            tests: Vec::new(),
            stats,
        }
    }

    /// Add a test to the suite.
    pub fn add_test(&mut self, entry: TestEntry) {
        self.tests.push(entry);
    }

    /// Get the number of tests.
    pub fn test_count(&self) -> usize {
        self.tests.len()
    }

    /// Finalize stats.
    pub fn finalize_stats(&mut self) {
        self.stats.test_count = self.tests.len();
        self.stats.suite_duration_ms = self.stats.suite_start_time.elapsed().as_secs_f64() * 1000.0;

        // Calculate grouping stats
        if !self.tests.is_empty() {
            let migration_groups: Vec<Vec<usize>> = {
                let mut groups: Vec<Vec<usize>> = Vec::new();
                let mut current_migration = self.tests[0].requires_migration;
                let mut current_group: Vec<usize> = vec![0];

                for i in 1..self.tests.len() {
                    if self.tests[i].requires_migration == current_migration {
                        current_group.push(i);
                    } else {
                        groups.push(current_group);
                        current_migration = self.tests[i].requires_migration;
                        current_group = vec![i];
                    }
                }
                groups.push(current_group);
                groups
            };

            let group_sizes: Vec<usize> = migration_groups.iter().map(|g| g.len()).collect();
            let total_tests_in_groups: usize = group_sizes.iter().sum();

            self.stats.grouping_stats = Some(GroupingStats {
                total_groups: migration_groups.len(),
                average_tests_per_group: if migration_groups.is_empty() {
                    0.0
                } else {
                    total_tests_in_groups as f64 / migration_groups.len() as f64
                },
                largest_group_size: group_sizes.iter().copied().max().unwrap_or(0),
                smallest_group_size: group_sizes.iter().copied().min().unwrap_or(0),
                groups_with_multiple_tests: group_sizes.iter().filter(|&&s| s > 1).count(),
                total_tests_in_groups,
            });
        }
    }

    /// Print a statistics summary.
    pub fn print_stats(&self) {
        let dash = "─".repeat(80);
        println!("\n{dash}");
        println!("TEST SUITE STATISTICS: {}", self.stats.suite_name);
        println!("{dash}");
        println!("  Tests: {}", self.stats.test_count);
        println!("  Migrations: {}", self.stats.migration_count);
        println!(
            "  Total Migration Time: {:.2}ms",
            self.stats.total_migration_time_ms
        );
        println!(
            "  Suite Duration: {:.2}ms",
            self.stats.suite_duration_ms
        );

        if let Some(ref gs) = self.stats.grouping_stats {
            println!("  Test Groups: {}", gs.total_groups);
            if gs.total_groups > 0 {
                println!(
                    "    Avg Tests/Group: {:.2}",
                    gs.average_tests_per_group
                );
                println!("    Largest Group: {}", gs.largest_group_size);
                println!("    Smallest Group: {}", gs.smallest_group_size);
                println!(
                    "    Groups w/ Multiple Tests: {}",
                    gs.groups_with_multiple_tests
                );
            }
        }

        println!("{dash}\n");
    }
}

// ─── Model generators ───────────────────────────────────────────────
//
// Maps to TS `generateModel("user" | "session" | "verification" | "account")`.

/// Generate a random user record for testing.
pub fn generate_test_user() -> serde_json::Value {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let random_past = chrono::Utc::now()
        - chrono::TimeDelta::seconds(rand::random::<u32>() as i64 % (365 * 24 * 3600));

    serde_json::json!({
        "id": id,
        "createdAt": random_past.to_rfc3339(),
        "updatedAt": now,
        "email": format!("user-{}@email.com", &id[..8]),
        "emailVerified": true,
        "name": format!("user-{}", &id[..8]),
        "image": null,
    })
}

/// Generate a random session record for testing.
pub fn generate_test_session(user_id: &str) -> serde_json::Value {
    let id = uuid::Uuid::new_v4().to_string();
    let token = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let random_past = chrono::Utc::now()
        - chrono::TimeDelta::seconds(rand::random::<u32>() as i64 % (365 * 24 * 3600));
    let expires_at = chrono::Utc::now()
        + chrono::TimeDelta::seconds(7 * 24 * 3600);

    serde_json::json!({
        "id": id,
        "createdAt": random_past.to_rfc3339(),
        "updatedAt": now,
        "expiresAt": expires_at.to_rfc3339(),
        "token": token,
        "userId": user_id,
        "ipAddress": "127.0.0.1",
        "userAgent": "TestAgent/1.0",
    })
}

/// Generate a random verification record for testing.
pub fn generate_test_verification() -> serde_json::Value {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let random_past = chrono::Utc::now()
        - chrono::TimeDelta::seconds(rand::random::<u32>() as i64 % (365 * 24 * 3600));
    let expires_at = chrono::Utc::now()
        + chrono::TimeDelta::seconds(3600);

    serde_json::json!({
        "id": id,
        "createdAt": random_past.to_rfc3339(),
        "updatedAt": now,
        "expiresAt": expires_at.to_rfc3339(),
        "identifier": format!("test:{}", uuid::Uuid::new_v4()),
        "value": uuid::Uuid::new_v4().to_string(),
    })
}

/// Generate a random account record for testing.
pub fn generate_test_account(user_id: &str) -> serde_json::Value {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let random_past = chrono::Utc::now()
        - chrono::TimeDelta::seconds(rand::random::<u32>() as i64 % (365 * 24 * 3600));
    let expires_at = chrono::Utc::now()
        + chrono::TimeDelta::seconds(3600);

    serde_json::json!({
        "id": id,
        "createdAt": random_past.to_rfc3339(),
        "updatedAt": now,
        "accountId": uuid::Uuid::new_v4().to_string(),
        "providerId": "test",
        "userId": user_id,
        "accessToken": uuid::Uuid::new_v4().to_string(),
        "refreshToken": uuid::Uuid::new_v4().to_string(),
        "idToken": uuid::Uuid::new_v4().to_string(),
        "accessTokenExpiresAt": expires_at.to_rfc3339(),
        "refreshTokenExpiresAt": expires_at.to_rfc3339(),
        "scope": "test",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_test_user() {
        let user = generate_test_user();
        assert!(user["id"].is_string());
        assert!(user["email"].is_string());
        assert!(user["name"].is_string());
        assert_eq!(user["emailVerified"], true);
    }

    #[test]
    fn test_generate_test_session() {
        let session = generate_test_session("user-123");
        assert!(session["id"].is_string());
        assert_eq!(session["userId"], "user-123");
        assert!(session["token"].is_string());
    }

    #[test]
    fn test_generate_test_verification() {
        let verification = generate_test_verification();
        assert!(verification["id"].is_string());
        assert!(verification["identifier"].is_string());
        assert!(verification["value"].is_string());
    }

    #[test]
    fn test_generate_test_account() {
        let account = generate_test_account("user-456");
        assert!(account["id"].is_string());
        assert_eq!(account["userId"], "user-456");
        assert_eq!(account["providerId"], "test");
    }

    #[test]
    fn test_suite_creation() {
        let suite = TestSuite::new("test-suite", false);
        assert_eq!(suite.config.name, "test-suite");
        assert_eq!(suite.test_count(), 0);
    }

    #[test]
    fn test_suite_stats() {
        let mut suite = TestSuite::new("stats-test", true);
        suite.finalize_stats();
        assert_eq!(suite.stats.test_count, 0);
        assert!(suite.stats.suite_duration_ms >= 0.0);
    }
}
