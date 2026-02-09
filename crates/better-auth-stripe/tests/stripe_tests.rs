//! Stripe plugin integration tests.
//!
//! Covers: webhook signature verification, event parsing,
//! subscription status, entitlements, config, types, and errors.

use better_auth_stripe::*;
use better_auth_stripe::webhook::*;
use chrono::Utc;

// ── Webhook signature ───────────────────────────────────────────

#[test]
fn verify_valid_webhook_signature() {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;

    let secret = "whsec_test_secret_key";
    let payload = b"{\"type\":\"checkout.session.completed\"}";
    let timestamp = "1614556800";

    let signed = format!("{}.{}", timestamp, std::str::from_utf8(payload).unwrap());
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(signed.as_bytes());
    let sig = hex::encode(mac.finalize().into_bytes());

    let header = format!("t={},v1={}", timestamp, sig);
    assert!(verify_webhook_signature(payload, &header, secret).is_ok());
}

#[test]
fn reject_invalid_webhook_signature() {
    let result = verify_webhook_signature(
        b"payload",
        "t=123,v1=definitely_invalid",
        "secret",
    );
    assert!(result.is_err());
}

#[test]
fn reject_missing_timestamp() {
    let result = verify_webhook_signature(b"payload", "v1=abc", "secret");
    assert!(result.is_err());
}

#[test]
fn reject_missing_signature() {
    let result = verify_webhook_signature(b"payload", "t=123", "secret");
    assert!(result.is_err());
}

#[test]
fn reject_empty_header() {
    let result = verify_webhook_signature(b"payload", "", "secret");
    assert!(result.is_err());
}

// ── Supported events ────────────────────────────────────────────

#[test]
fn checkout_session_completed_is_supported() {
    assert!(is_supported_event("checkout.session.completed"));
}

#[test]
fn subscription_events_are_supported() {
    assert!(is_supported_event("customer.subscription.created"));
    assert!(is_supported_event("customer.subscription.updated"));
    assert!(is_supported_event("customer.subscription.deleted"));
}

#[test]
fn invoice_events_are_supported() {
    assert!(is_supported_event("invoice.paid"));
    assert!(is_supported_event("invoice.payment_failed"));
}

#[test]
fn customer_events_are_supported() {
    assert!(is_supported_event("customer.created"));
    assert!(is_supported_event("customer.updated"));
    assert!(is_supported_event("customer.deleted"));
}

#[test]
fn unknown_event_not_supported() {
    assert!(!is_supported_event("unknown.event"));
    assert!(!is_supported_event("charge.succeeded"));
    assert!(!is_supported_event(""));
}

// ── Subscription status ─────────────────────────────────────────

#[test]
fn parse_active_status() {
    assert_eq!(parse_subscription_status("active"), SubscriptionStatus::Active);
}

#[test]
fn parse_canceled_status() {
    assert_eq!(parse_subscription_status("canceled"), SubscriptionStatus::Canceled);
}

#[test]
fn parse_trialing_status() {
    assert_eq!(parse_subscription_status("trialing"), SubscriptionStatus::Trialing);
}

#[test]
fn parse_past_due_status() {
    assert_eq!(parse_subscription_status("past_due"), SubscriptionStatus::PastDue);
}

#[test]
fn parse_unpaid_status() {
    assert_eq!(parse_subscription_status("unpaid"), SubscriptionStatus::Unpaid);
}

#[test]
fn parse_paused_status() {
    assert_eq!(parse_subscription_status("paused"), SubscriptionStatus::Paused);
}

#[test]
fn parse_incomplete_status() {
    assert_eq!(parse_subscription_status("incomplete"), SubscriptionStatus::Incomplete);
}

#[test]
fn parse_incomplete_expired_status() {
    assert_eq!(parse_subscription_status("incomplete_expired"), SubscriptionStatus::IncompleteExpired);
}

#[test]
fn parse_unknown_defaults_to_incomplete() {
    assert_eq!(parse_subscription_status("unknown_status"), SubscriptionStatus::Incomplete);
}

// ── Entitlement computation ─────────────────────────────────────

#[test]
fn active_subscription_entitlement() {
    let sub = Subscription {
        id: "sub1".into(),
        user_id: "u1".into(),
        stripe_subscription_id: "sub_123".into(),
        stripe_customer_id: "cus_123".into(),
        plan_id: "pro".into(),
        status: SubscriptionStatus::Active,
        current_period_start: Utc::now(),
        current_period_end: Utc::now(),
        cancel_at_period_end: false,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let plan = Plan {
        id: "pro".into(),
        name: "Pro Plan".into(),
        stripe_price_id: "price_123".into(),
        features: vec!["feature_a".into(), "feature_b".into()],
        limits: Default::default(),
    };
    let ent = compute_entitlement(&sub, &plan);
    assert!(ent.is_active);
    assert_eq!(ent.plan_id, "pro");
    assert_eq!(ent.features.len(), 2);
    assert!(ent.expires_at.is_some());
}

#[test]
fn trialing_subscription_is_active() {
    let sub = Subscription {
        id: "sub2".into(),
        user_id: "u2".into(),
        stripe_subscription_id: "sub_trial".into(),
        stripe_customer_id: "cus_trial".into(),
        plan_id: "starter".into(),
        status: SubscriptionStatus::Trialing,
        current_period_start: Utc::now(),
        current_period_end: Utc::now(),
        cancel_at_period_end: false,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let plan = Plan {
        id: "starter".into(),
        name: "Starter".into(),
        stripe_price_id: "price_starter".into(),
        features: vec!["basic".into()],
        limits: Default::default(),
    };
    let ent = compute_entitlement(&sub, &plan);
    assert!(ent.is_active);
}

#[test]
fn canceled_subscription_not_active() {
    let sub = Subscription {
        id: "sub3".into(),
        user_id: "u3".into(),
        stripe_subscription_id: "sub_canceled".into(),
        stripe_customer_id: "cus_canceled".into(),
        plan_id: "pro".into(),
        status: SubscriptionStatus::Canceled,
        current_period_start: Utc::now(),
        current_period_end: Utc::now(),
        cancel_at_period_end: false,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let plan = Plan {
        id: "pro".into(),
        name: "Pro".into(),
        stripe_price_id: "price_pro".into(),
        features: vec![],
        limits: Default::default(),
    };
    let ent = compute_entitlement(&sub, &plan);
    assert!(!ent.is_active);
}

// ── Config ──────────────────────────────────────────────────────

#[test]
fn stripe_options_find_plan() {
    let opts = StripeOptions {
        secret_key: "sk_test".into(),
        webhook_secret: "whsec_test".into(),
        plans: vec![
            Plan {
                id: "pro".into(),
                name: "Pro".into(),
                stripe_price_id: "price_pro".into(),
                features: vec![],
                limits: Default::default(),
            },
        ],
        auto_create_customer: true,
        default_success_url: "/success".into(),
        default_cancel_url: "/cancel".into(),
    };
    assert!(opts.find_plan("pro").is_some());
    assert!(opts.find_plan("nonexistent").is_none());
    assert!(opts.find_plan_by_price("price_pro").is_some());
}

// ── Types serde ─────────────────────────────────────────────────

#[test]
fn subscription_status_serde() {
    let status = SubscriptionStatus::Active;
    let json = serde_json::to_string(&status).unwrap();
    assert_eq!(json, "\"active\"");
    let parsed: SubscriptionStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, SubscriptionStatus::Active);
}

#[test]
fn webhook_event_deser() {
    let v = serde_json::json!({
        "id": "evt_1",
        "type": "checkout.session.completed",
        "data": {
            "object": {"id": "cs_test"}
        },
        "created": 1714000000
    });
    let event: WebhookEvent = serde_json::from_value(v).unwrap();
    assert_eq!(event.event_type, "checkout.session.completed");
    assert_eq!(event.data.object["id"], "cs_test");
}

#[test]
fn checkout_session_serde() {
    let session = CheckoutSession {
        url: "https://checkout.stripe.com/session".into(),
        session_id: "cs_test_123".into(),
    };
    let v = serde_json::to_value(&session).unwrap();
    assert_eq!(v["session_id"], "cs_test_123");
}

#[test]
fn error_display() {
    let err = StripeError::WebhookSignatureInvalid;
    assert!(!format!("{}", err).is_empty());
}
