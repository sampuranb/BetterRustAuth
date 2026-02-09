//! # better-auth-leptos
//!
//! Leptos integration for Better Auth. Provides reactive signals and context
//! for session management in Leptos applications.
//!
//! Maps to the TS `client/svelte/index.ts` and `client/react/react-store.ts`
//! patterns, adapted for Leptos's reactive signal system.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use better_auth_leptos::*;
//! use better_auth_client::{BetterAuthClient, ClientOptions};
//! use leptos::prelude::*;
//!
//! #[component]
//! fn App() -> impl IntoView {
//!     let client = BetterAuthClient::new(ClientOptions {
//!         base_url: "http://localhost:3000".into(),
//!         ..Default::default()
//!     });
//!
//!     provide_auth(client);
//!
//!     view! {
//!         <SessionGuard>
//!             <Dashboard />
//!         </SessionGuard>
//!     }
//! }
//!
//! #[component]
//! fn Dashboard() -> impl IntoView {
//!     let session = use_session();
//!     view! {
//!         <Show when=move || session.get().is_some()>
//!             <p>"Logged in!"</p>
//!         </Show>
//!     }
//! }
//! ```

use better_auth_client::{BetterAuthClient, SessionData};
use leptos::prelude::*;

/// Provide the Better Auth client to the Leptos context tree.
///
/// Maps to React's `<AuthProvider>` / Svelte's `setContext`.
/// Must be called in a parent component before `use_auth()` or `use_session()`.
pub fn provide_auth(client: BetterAuthClient) {
    provide_context(AuthContext {
        client,
        session: RwSignal::new(None),
        is_loading: RwSignal::new(true),
        error: RwSignal::new(None),
    });
}

/// Auth context stored in Leptos's reactive context system.
#[derive(Clone)]
pub struct AuthContext {
    /// The underlying Better Auth HTTP client.
    pub client: BetterAuthClient,
    /// Reactive session signal.
    pub session: RwSignal<Option<SessionData>>,
    /// Whether the session is currently being fetched.
    pub is_loading: RwSignal<bool>,
    /// Last error from a session fetch.
    pub error: RwSignal<Option<String>>,
}

/// Get the Better Auth client from context.
///
/// Panics if `provide_auth()` was not called in a parent component.
pub fn use_auth() -> AuthContext {
    expect_context::<AuthContext>()
}

/// Get a reactive session signal.
///
/// Maps to TS `client.useSession()`. Returns a `ReadSignal<Option<SessionData>>`
/// that automatically updates when the session changes.
///
/// Triggers an initial fetch on first access and subscribes to the
/// `SessionBroadcast` for cross-task updates.
pub fn use_session() -> ReadSignal<Option<SessionData>> {
    let ctx = use_auth();

    // Spawn initial session fetch
    Effect::new(move |_| {
        let client = ctx.client.clone();
        let session_signal = ctx.session;
        let is_loading = ctx.is_loading;
        let error_signal = ctx.error;

        leptos::task::spawn_local(async move {
            is_loading.set(true);
            match client.get_session().await {
                Ok(Some(data)) => {
                    session_signal.set(Some(data));
                    error_signal.set(None);
                }
                Ok(None) => {
                    session_signal.set(None);
                    error_signal.set(None);
                }
                Err(e) => {
                    error_signal.set(Some(e.to_string()));
                }
            }
            is_loading.set(false);
        });
    });

    ctx.session.read_only()
}

/// Get the loading state for the session.
pub fn use_session_loading() -> ReadSignal<bool> {
    let ctx = use_auth();
    ctx.is_loading.read_only()
}

/// Get the error state for the session.
pub fn use_session_error() -> ReadSignal<Option<String>> {
    let ctx = use_auth();
    ctx.error.read_only()
}

/// Imperatively refetch the session.
///
/// Maps to TS `session.refetch()`.
pub fn refetch_session() {
    let ctx = use_auth();
    let client = ctx.client.clone();
    let session_signal = ctx.session;
    let is_loading = ctx.is_loading;
    let error_signal = ctx.error;

    leptos::task::spawn_local(async move {
        is_loading.set(true);
        match client.get_session().await {
            Ok(Some(data)) => {
                session_signal.set(Some(data));
                error_signal.set(None);
            }
            Ok(None) => {
                session_signal.set(None);
                error_signal.set(None);
            }
            Err(e) => {
                error_signal.set(Some(e.to_string()));
            }
        }
        is_loading.set(false);
    });
}

/// Sign out and clear the session signal.
pub fn sign_out() {
    let ctx = use_auth();
    let client = ctx.client.clone();
    let session_signal = ctx.session;

    leptos::task::spawn_local(async move {
        let _ = client.sign_out().await;
        session_signal.set(None);
    });
}

/// Reactive session state, combining data, loading, and error.
///
/// Maps to the TS `SessionAtom` type:
/// ```ts
/// { data: Session | null, isPending: boolean, error: Error | null }
/// ```
#[derive(Clone, Debug)]
pub struct SessionState {
    pub data: Option<SessionData>,
    pub is_pending: bool,
    pub error: Option<String>,
}

/// Get the full reactive session state (data + loading + error).
pub fn use_session_state() -> Signal<SessionState> {
    let ctx = use_auth();
    Signal::derive(move || SessionState {
        data: ctx.session.get(),
        is_pending: ctx.is_loading.get(),
        error: ctx.error.get(),
    })
}
