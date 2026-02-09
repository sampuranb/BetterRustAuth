//! Stripe configuration.

use crate::types::Plan;
use serde::{Deserialize, Serialize};

/// Stripe plugin configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeOptions {
    /// Stripe secret key.
    pub secret_key: String,
    /// Stripe webhook signing secret.
    pub webhook_secret: String,
    /// Available subscription plans.
    #[serde(default)]
    pub plans: Vec<Plan>,
    /// Auto-create Stripe customer on user signup.
    #[serde(default = "default_true")]
    pub auto_create_customer: bool,
    /// Success URL for checkout.
    #[serde(default = "default_success_url")]
    pub default_success_url: String,
    /// Cancel URL for checkout.
    #[serde(default = "default_cancel_url")]
    pub default_cancel_url: String,
}

fn default_true() -> bool { true }
fn default_success_url() -> String { "/payment/success".to_string() }
fn default_cancel_url() -> String { "/payment/cancel".to_string() }

impl StripeOptions {
    /// Find a plan by ID.
    pub fn find_plan(&self, plan_id: &str) -> Option<&Plan> {
        self.plans.iter().find(|p| p.id == plan_id)
    }

    /// Find a plan by Stripe price ID.
    pub fn find_plan_by_price(&self, price_id: &str) -> Option<&Plan> {
        self.plans.iter().find(|p| p.stripe_price_id == price_id)
    }
}
