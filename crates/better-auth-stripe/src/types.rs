//! Stripe types — customers, subscriptions, plans, entitlements.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Stripe customer linked to an auth user.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StripeCustomer {
    pub id: String,
    pub user_id: String,
    pub stripe_customer_id: String,
    pub email: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Subscription record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    pub id: String,
    pub user_id: String,
    pub stripe_subscription_id: String,
    pub stripe_customer_id: String,
    pub plan_id: String,
    pub status: SubscriptionStatus,
    pub current_period_start: DateTime<Utc>,
    pub current_period_end: DateTime<Utc>,
    pub cancel_at_period_end: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Subscription statuses.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SubscriptionStatus {
    Active,
    Canceled,
    Incomplete,
    IncompleteExpired,
    PastDue,
    Trialing,
    Unpaid,
    Paused,
}

/// Subscription plan definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    pub id: String,
    pub name: String,
    pub stripe_price_id: String,
    pub features: Vec<String>,
    pub limits: std::collections::HashMap<String, serde_json::Value>,
}

/// Checkout session request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateCheckoutRequest {
    pub plan_id: String,
    pub success_url: String,
    pub cancel_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trial_period_days: Option<u32>,
}

/// Checkout session response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckoutSession {
    pub url: String,
    pub session_id: String,
}

/// Stripe webhook event (simplified).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEvent {
    pub id: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub data: WebhookEventData,
    pub created: i64,
}

/// Webhook event data object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebhookEventData {
    pub object: serde_json::Value,
}

/// Entitlement — computed access based on subscription plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entitlement {
    pub plan_id: String,
    pub features: Vec<String>,
    pub is_active: bool,
    pub expires_at: Option<DateTime<Utc>>,
}
