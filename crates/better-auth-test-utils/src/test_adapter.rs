// Test adapter runner — mirrors packages/test-utils/src/adapter/test-adapter.ts
//
// The `TestAdapter` orchestrates running test suites against a database adapter:
// 1. Runs migrations
// 2. Executes each test suite
// 3. Cleans up after each suite
// 4. Reports aggregate statistics

use std::time::Instant;

use crate::test_suite::{TestHelpers, TestLogger, TestSuite, TestSuiteStats};

/// Configuration for the test adapter runner.
pub struct TestAdapterConfig {
    /// Display name for the adapter being tested.
    pub adapter_display_name: String,
    /// Function to run database migrations.
    pub run_migrations: Box<dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Box<dyn std::error::Error>>> + Send>> + Send + Sync>,
    /// Additional cleanup function.
    pub additional_cleanup: Option<Box<dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Box<dyn std::error::Error>>> + Send>> + Send + Sync>>,
    /// Test suites to run.
    pub test_suites: Vec<TestSuite>,
    /// Prefix to add to test suite names.
    pub prefix_tests: Option<String>,
    /// Callback when all tests finish.
    pub on_finish: Option<Box<dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> + Send + Sync>>,
}

/// The test adapter runner.
///
/// Maps to TS `testAdapter({ adapter, runMigrations, tests, ... })`.
pub struct TestAdapter {
    config: TestAdapterConfig,
    log: TestLogger,
    all_stats: Vec<TestSuiteStats>,
}

impl TestAdapter {
    /// Create a new test adapter runner.
    pub fn new(config: TestAdapterConfig) -> Self {
        let log = TestLogger::new(&config.adapter_display_name);
        Self {
            config,
            log,
            all_stats: Vec::new(),
        }
    }

    /// Run all test suites.
    ///
    /// Maps to TS `testAdapter.execute()`.
    pub async fn execute(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.log.info("Starting test adapter execution");

        // Run migrations
        let migration_start = Instant::now();
        (self.config.run_migrations)().await?;
        let migration_time = migration_start.elapsed().as_secs_f64() * 1000.0;
        self.log.success(&format!(
            "MIGRATIONS completed successfully ({:.3}ms)",
            migration_time
        ));

        // Run each test suite
        for suite in &mut self.config.test_suites {
            let suite_name = if let Some(ref prefix) = self.config.prefix_tests {
                format!("{} > {}", prefix, suite.config.name)
            } else {
                suite.config.name.clone()
            };

            self.log.info(&format!("Running suite: {}", suite_name));
            suite.stats.suite_start_time = Instant::now();

            // Run tests
            for test in &suite.tests {
                // Migrations if needed
                if test.requires_migration && suite.config.always_migrate {
                    let mig_start = Instant::now();
                    (self.config.run_migrations)().await?;
                    let mig_time = mig_start.elapsed().as_secs_f64() * 1000.0;
                    suite.stats.migration_count += 1;
                    suite.stats.total_migration_time_ms += mig_time;
                }

                self.log.info(&format!("  Running test: {}", test.name));

                let helpers = TestHelpers {
                    log: TestLogger::new(&self.config.adapter_display_name),
                };

                match (test.test_fn)(&helpers).await {
                    Ok(()) => {
                        self.log
                            .success(&format!("  ✓ {}", test.name));
                    }
                    Err(e) => {
                        self.log
                            .error(&format!("  ✗ {}: {}", test.name, e));
                        return Err(e);
                    }
                }
            }

            suite.finalize_stats();
            self.all_stats.push(suite.stats.clone());
        }

        // Cleanup
        let cleanup_start = Instant::now();
        if let Some(ref cleanup) = self.config.additional_cleanup {
            cleanup().await?;
        }
        let cleanup_time = cleanup_start.elapsed().as_secs_f64() * 1000.0;
        self.log.success(&format!(
            "CLEAN-UP completed successfully ({:.3}ms)",
            cleanup_time
        ));

        // Print aggregate stats
        self.print_aggregate_stats();

        // On finish callback
        if let Some(ref on_finish) = self.config.on_finish {
            on_finish().await;
        }

        Ok(())
    }

    /// Print aggregate statistics across all suites.
    fn print_aggregate_stats(&self) {
        if self.all_stats.is_empty() {
            return;
        }

        let total_migrations: usize = self.all_stats.iter().map(|s| s.migration_count).sum();
        let total_migration_time: f64 = self
            .all_stats
            .iter()
            .map(|s| s.total_migration_time_ms)
            .sum();
        let total_tests: usize = self.all_stats.iter().map(|s| s.test_count).sum();
        let total_duration: f64 = self
            .all_stats
            .iter()
            .map(|s| s.suite_duration_ms)
            .sum();

        let dash = "─".repeat(80);

        println!("\n{dash}");
        println!("TEST SUITE STATISTICS SUMMARY");
        println!("{dash}\n");

        // Per-suite breakdown
        for stats in &self.all_stats {
            let avg_migration_time = if stats.migration_count > 0 {
                stats.total_migration_time_ms / stats.migration_count as f64
            } else {
                0.0
            };

            println!("{}:", stats.suite_name);
            println!("  Tests: {}", stats.test_count);
            println!(
                "  Migrations: {} (avg: {:.2}ms)",
                stats.migration_count, avg_migration_time
            );
            println!(
                "  Total Migration Time: {:.2}ms",
                stats.total_migration_time_ms
            );
            println!("  Suite Duration: {:.2}ms", stats.suite_duration_ms);

            if let Some(ref gs) = stats.grouping_stats {
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

            println!();
        }

        // Totals
        let avg = if total_migrations > 0 {
            total_migration_time / total_migrations as f64
        } else {
            0.0
        };

        println!("{dash}");
        println!("TOTALS");
        println!("  Total Tests: {}", total_tests);
        println!(
            "  Total Migrations: {} (avg: {:.2}ms)",
            total_migrations, avg
        );
        println!(
            "  Total Migration Time: {:.2}ms",
            total_migration_time
        );
        println!("  Total Duration: {:.2}ms", total_duration);

        // Total grouping stats
        let total_groups: usize = self
            .all_stats
            .iter()
            .map(|s| s.grouping_stats.as_ref().map(|g| g.total_groups).unwrap_or(0))
            .sum();

        if total_groups > 0 {
            let total_multi = self
                .all_stats
                .iter()
                .map(|s| {
                    s.grouping_stats
                        .as_ref()
                        .map(|g| g.groups_with_multiple_tests)
                        .unwrap_or(0)
                })
                .sum::<usize>();
            let total_in_groups = self
                .all_stats
                .iter()
                .map(|s| {
                    s.grouping_stats
                        .as_ref()
                        .map(|g| g.total_tests_in_groups)
                        .unwrap_or(0)
                })
                .sum::<usize>();

            let avg_per_group = if total_groups > 0 {
                total_in_groups as f64 / total_groups as f64
            } else {
                0.0
            };

            println!("  Total Test Groups: {}", total_groups);
            println!("    Avg Tests/Group: {:.2}", avg_per_group);
            println!(
                "    Groups w/ Multiple Tests: {}",
                total_multi
            );
        }

        println!("{dash}\n");
    }

    /// Get all collected statistics.
    pub fn stats(&self) -> &[TestSuiteStats] {
        &self.all_stats
    }
}

/// Convenience function for creating a simple test result.
pub fn try_catch<T, E>(
    result: Result<T, E>,
) -> (Option<T>, Option<E>) {
    match result {
        Ok(data) => (Some(data), None),
        Err(err) => (None, Some(err)),
    }
}

/// Deep equality comparison for serde_json::Value.
///
/// Maps to TS `deepEqual(a, b)`.
pub fn deep_equal(a: &serde_json::Value, b: &serde_json::Value) -> bool {
    a == b
}

/// Deep merge two JSON values.
///
/// Maps to TS `deepmerge(a, b)`.
pub fn deep_merge(
    base: &serde_json::Value,
    overlay: &serde_json::Value,
) -> serde_json::Value {
    match (base, overlay) {
        (serde_json::Value::Object(a), serde_json::Value::Object(b)) => {
            let mut merged = a.clone();
            for (k, v) in b {
                let existing = merged.get(k).cloned().unwrap_or(serde_json::Value::Null);
                merged.insert(k.clone(), deep_merge(&existing, v));
            }
            serde_json::Value::Object(merged)
        }
        (_, overlay) => overlay.clone(),
    }
}

/// Sort models by ID or createdAt.
pub fn sort_models(
    models: &mut Vec<serde_json::Value>,
    by: &str,
) {
    models.sort_by(|a, b| {
        if by == "createdAt" {
            let a_date = a["createdAt"].as_str().unwrap_or("");
            let b_date = b["createdAt"].as_str().unwrap_or("");
            a_date.cmp(b_date)
        } else {
            let a_id = a["id"].as_str().unwrap_or("");
            let b_id = b["id"].as_str().unwrap_or("");
            a_id.cmp(b_id)
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deep_equal() {
        let a = serde_json::json!({"foo": "bar", "nested": {"a": 1}});
        let b = serde_json::json!({"foo": "bar", "nested": {"a": 1}});
        let c = serde_json::json!({"foo": "baz"});

        assert!(deep_equal(&a, &b));
        assert!(!deep_equal(&a, &c));
    }

    #[test]
    fn test_deep_merge() {
        let base = serde_json::json!({"a": 1, "b": {"c": 2}});
        let overlay = serde_json::json!({"b": {"d": 3}, "e": 4});
        let merged = deep_merge(&base, &overlay);

        assert_eq!(merged["a"], 1);
        assert_eq!(merged["b"]["c"], 2);
        assert_eq!(merged["b"]["d"], 3);
        assert_eq!(merged["e"], 4);
    }

    #[test]
    fn test_sort_models() {
        let mut models = vec![
            serde_json::json!({"id": "c", "name": "third"}),
            serde_json::json!({"id": "a", "name": "first"}),
            serde_json::json!({"id": "b", "name": "second"}),
        ];

        sort_models(&mut models, "id");
        assert_eq!(models[0]["id"], "a");
        assert_eq!(models[1]["id"], "b");
        assert_eq!(models[2]["id"], "c");
    }

    #[test]
    fn test_try_catch_ok() {
        let result: Result<i32, String> = Ok(42);
        let (data, err) = try_catch(result);
        assert_eq!(data, Some(42));
        assert!(err.is_none());
    }

    #[test]
    fn test_try_catch_err() {
        let result: Result<i32, String> = Err("fail".to_string());
        let (data, err) = try_catch(result);
        assert!(data.is_none());
        assert_eq!(err, Some("fail".to_string()));
    }
}
