//! Stripe webhook signature verification and event processing.

use crate::error::StripeError;
use crate::types::*;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Verify a Stripe webhook signature.
/// Maps to TS webhook signature verification logic.
///
/// Stripe-Signature header format: `t=<timestamp>,v1=<signature>`
pub fn verify_webhook_signature(
    payload: &[u8],
    signature_header: &str,
    webhook_secret: &str,
) -> Result<(), StripeError> {
    let parts: std::collections::HashMap<&str, &str> = signature_header
        .split(',')
        .filter_map(|part| {
            let mut kv = part.splitn(2, '=');
            Some((kv.next()?, kv.next()?))
        })
        .collect();

    let timestamp = parts.get("t").ok_or(StripeError::WebhookSignatureInvalid)?;
    let signature = parts.get("v1").ok_or(StripeError::WebhookSignatureInvalid)?;

    // Build the signed payload: timestamp.payload
    let signed_payload = format!("{}.{}", timestamp, std::str::from_utf8(payload)
        .map_err(|_| StripeError::WebhookSignatureInvalid)?);

    let mut mac = HmacSha256::new_from_slice(webhook_secret.as_bytes())
        .map_err(|_| StripeError::WebhookSignatureInvalid)?;
    mac.update(signed_payload.as_bytes());

    let expected = hex::encode(mac.finalize().into_bytes());

    // Constant-time comparison
    if subtle::ConstantTimeEq::ct_eq(expected.as_bytes(), signature.as_bytes()).into() {
        Ok(())
    } else {
        Err(StripeError::WebhookSignatureInvalid)
    }
}

/// Supported webhook event types.
pub const SUPPORTED_EVENTS: &[&str] = &[
    "checkout.session.completed",
    "customer.subscription.created",
    "customer.subscription.updated",
    "customer.subscription.deleted",
    "invoice.paid",
    "invoice.payment_failed",
    "customer.created",
    "customer.updated",
    "customer.deleted",
];

/// Check if a webhook event type is supported.
pub fn is_supported_event(event_type: &str) -> bool {
    SUPPORTED_EVENTS.contains(&event_type)
}

/// Parse subscription status from a Stripe subscription object.
pub fn parse_subscription_status(status: &str) -> SubscriptionStatus {
    match status {
        "active" => SubscriptionStatus::Active,
        "canceled" => SubscriptionStatus::Canceled,
        "incomplete" => SubscriptionStatus::Incomplete,
        "incomplete_expired" => SubscriptionStatus::IncompleteExpired,
        "past_due" => SubscriptionStatus::PastDue,
        "trialing" => SubscriptionStatus::Trialing,
        "unpaid" => SubscriptionStatus::Unpaid,
        "paused" => SubscriptionStatus::Paused,
        _ => SubscriptionStatus::Incomplete,
    }
}

/// Build an entitlement from a subscription and plan.
pub fn compute_entitlement(subscription: &Subscription, plan: &crate::types::Plan) -> Entitlement {
    Entitlement {
        plan_id: plan.id.clone(),
        features: plan.features.clone(),
        is_active: subscription.status == SubscriptionStatus::Active
            || subscription.status == SubscriptionStatus::Trialing,
        expires_at: Some(subscription.current_period_end),
    }
}

use subtle;

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_verify_webhook_signature_valid() {
        let secret = "whsec_test_secret";
        let payload = b"{\"type\":\"test\"}";
        let timestamp = "1614556800";

        let signed_payload = format!("{}.{}", timestamp, std::str::from_utf8(payload).unwrap());
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(signed_payload.as_bytes());
        let sig = hex::encode(mac.finalize().into_bytes());

        let header = format!("t={},v1={}", timestamp, sig);
        assert!(verify_webhook_signature(payload, &header, secret).is_ok());
    }

    #[test]
    fn test_verify_webhook_signature_invalid() {
        let result = verify_webhook_signature(
            b"payload",
            "t=123,v1=invalidsig",
            "secret",
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_is_supported_event() {
        assert!(is_supported_event("checkout.session.completed"));
        assert!(is_supported_event("customer.subscription.updated"));
        assert!(!is_supported_event("unknown.event"));
    }

    #[test]
    fn test_parse_subscription_status() {
        assert_eq!(parse_subscription_status("active"), SubscriptionStatus::Active);
        assert_eq!(parse_subscription_status("canceled"), SubscriptionStatus::Canceled);
        assert_eq!(parse_subscription_status("trialing"), SubscriptionStatus::Trialing);
        assert_eq!(parse_subscription_status("unknown"), SubscriptionStatus::Incomplete);
    }

    #[test]
    fn test_compute_entitlement() {
        let sub = Subscription {
            id: "sub1".into(), user_id: "u1".into(), stripe_subscription_id: "sub_123".into(),
            stripe_customer_id: "cus_123".into(), plan_id: "pro".into(),
            status: SubscriptionStatus::Active,
            current_period_start: Utc::now(), current_period_end: Utc::now(),
            cancel_at_period_end: false, created_at: Utc::now(), updated_at: Utc::now(),
        };
        let plan = crate::types::Plan {
            id: "pro".into(), name: "Pro".into(), stripe_price_id: "price_123".into(),
            features: vec!["feature1".into(), "feature2".into()],
            limits: Default::default(),
        };
        let ent = compute_entitlement(&sub, &plan);
        assert!(ent.is_active);
        assert_eq!(ent.features.len(), 2);
    }
}
