//! # better-auth-dioxus
//!
//! Dioxus integration for Better Auth. Provides hooks and context for
//! session management in Dioxus web applications.
//!
//! Maps to the TS `client/react/react-store.ts` pattern, adapted for
//! Dioxus's hook and signal system.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use better_auth_dioxus::*;
//! use better_auth_client::{BetterAuthClient, ClientOptions};
//! use dioxus::prelude::*;
//!
//! fn App() -> Element {
//!     let client = BetterAuthClient::new(ClientOptions {
//!         base_url: "http://localhost:3000".into(),
//!         ..Default::default()
//!     });
//!     provide_auth(client);
//!
//!     rsx! { Dashboard {} }
//! }
//!
//! fn Dashboard() -> Element {
//!     let session = use_session();
//!     rsx! {
//!         if let Some(data) = session.read().as_ref() {
//!             p { "Logged in!" }
//!         }
//!     }
//! }
//! ```

use better_auth_client::{BetterAuthClient, SessionData};
use dioxus::prelude::*;

/// Auth context for Dioxus.
#[derive(Clone)]
pub struct AuthContext {
    /// The underlying Better Auth HTTP client.
    pub client: BetterAuthClient,
    /// Reactive session signal.
    pub session: Signal<Option<SessionData>>,
    /// Whether the session is currently being fetched.
    pub is_loading: Signal<bool>,
    /// Last error from a session fetch.
    pub error: Signal<Option<String>>,
}

/// Provide the Better Auth client to the Dioxus context tree.
///
/// Maps to React's `<AuthProvider>`.
/// Must be called in App or a parent component before `use_auth()`.
pub fn provide_auth(client: BetterAuthClient) {
    let ctx = AuthContext {
        client,
        session: Signal::new(None),
        is_loading: Signal::new(true),
        error: Signal::new(None),
    };
    provide_context(ctx);
}

/// Get the auth context from Dioxus context.
///
/// Panics if `provide_auth()` was not called.
pub fn use_auth() -> AuthContext {
    consume_context::<AuthContext>()
}

/// Hook to get the reactive session signal.
///
/// Maps to TS `client.useSession()`.
/// Returns a `Signal<Option<SessionData>>` that updates automatically.
///
/// Triggers an initial session fetch.
pub fn use_session() -> Signal<Option<SessionData>> {
    let ctx = use_auth();

    // Initial fetch
    let _ = use_resource(move || {
        let client = ctx.client.clone();
        let mut session = ctx.session;
        let mut is_loading = ctx.is_loading;
        let mut error_signal = ctx.error;
        async move {
            is_loading.set(true);
            match client.get_session().await {
                Ok(Some(data)) => {
                    session.set(Some(data));
                    error_signal.set(None);
                }
                Ok(None) => {
                    session.set(None);
                    error_signal.set(None);
                }
                Err(e) => {
                    error_signal.set(Some(e.to_string()));
                }
            }
            is_loading.set(false);
        }
    });

    ctx.session
}

/// Get the loading state signal.
pub fn use_session_loading() -> Signal<bool> {
    let ctx = use_auth();
    ctx.is_loading
}

/// Get the error signal.
pub fn use_session_error() -> Signal<Option<String>> {
    let ctx = use_auth();
    ctx.error
}

/// Imperatively refetch the session.
pub async fn refetch_session() {
    let mut ctx = consume_context::<AuthContext>();
    ctx.is_loading.set(true);
    match ctx.client.get_session().await {
        Ok(Some(data)) => {
            ctx.session.set(Some(data));
            ctx.error.set(None);
        }
        Ok(None) => {
            ctx.session.set(None);
            ctx.error.set(None);
        }
        Err(e) => {
            ctx.error.set(Some(e.to_string()));
        }
    }
    ctx.is_loading.set(false);
}

/// Sign out and clear session.
pub async fn sign_out() {
    let mut ctx = consume_context::<AuthContext>();
    let _ = ctx.client.sign_out().await;
    ctx.session.set(None);
}

/// Combined session state.
#[derive(Clone, Debug)]
pub struct SessionState {
    pub data: Option<SessionData>,
    pub is_pending: bool,
    pub error: Option<String>,
}
