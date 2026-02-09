//! Stripe error codes.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StripeError {
    WebhookSignatureInvalid,
    WebhookEventNotSupported,
    CustomerNotFound,
    SubscriptionNotFound,
    CheckoutFailed,
    PortalFailed,
    CustomerSyncFailed,
    MissingStripeKey,
    InvalidPlan,
}

impl StripeError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::WebhookSignatureInvalid => "WEBHOOK_SIGNATURE_INVALID",
            Self::WebhookEventNotSupported => "WEBHOOK_EVENT_NOT_SUPPORTED",
            Self::CustomerNotFound => "CUSTOMER_NOT_FOUND",
            Self::SubscriptionNotFound => "SUBSCRIPTION_NOT_FOUND",
            Self::CheckoutFailed => "CHECKOUT_FAILED",
            Self::PortalFailed => "PORTAL_FAILED",
            Self::CustomerSyncFailed => "CUSTOMER_SYNC_FAILED",
            Self::MissingStripeKey => "MISSING_STRIPE_KEY",
            Self::InvalidPlan => "INVALID_PLAN",
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            Self::WebhookSignatureInvalid => "Webhook signature verification failed",
            Self::WebhookEventNotSupported => "Webhook event type not supported",
            Self::CustomerNotFound => "Stripe customer not found",
            Self::SubscriptionNotFound => "Subscription not found",
            Self::CheckoutFailed => "Failed to create checkout session",
            Self::PortalFailed => "Failed to create portal session",
            Self::CustomerSyncFailed => "Failed to sync customer",
            Self::MissingStripeKey => "Stripe API key is not configured",
            Self::InvalidPlan => "Invalid subscription plan",
        }
    }
}

impl std::fmt::Display for StripeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code(), self.message())
    }
}

impl std::error::Error for StripeError {}
