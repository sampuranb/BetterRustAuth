//! # better-auth-yew
//!
//! Yew integration for Better Auth. Provides hooks and context for
//! session management in Yew web applications.
//!
//! Maps to the TS `client/react/react-store.ts` pattern, adapted for
//! Yew's functional component and hook system.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use better_auth_yew::*;
//! use better_auth_client::{BetterAuthClient, ClientOptions};
//! use yew::prelude::*;
//!
//! #[function_component(App)]
//! fn app() -> Html {
//!     let client = BetterAuthClient::new(ClientOptions {
//!         base_url: "http://localhost:3000".into(),
//!         ..Default::default()
//!     });
//!
//!     html! {
//!         <AuthProvider {client}>
//!             <Dashboard />
//!         </AuthProvider>
//!     }
//! }
//!
//! #[function_component(Dashboard)]
//! fn dashboard() -> Html {
//!     let session = use_session();
//!     html! {
//!         if session.is_some() {
//!             <p>{ "Logged in!" }</p>
//!         }
//!     }
//! }
//! ```

use better_auth_client::{BetterAuthClient, SessionData};
use std::rc::Rc;
use yew::prelude::*;

/// Auth context value.
#[derive(Clone, Debug, PartialEq)]
pub struct AuthContextValue {
    /// Reactive session state.
    pub session: Option<SessionData>,
    /// Whether the session is loading.
    pub is_loading: bool,
    /// Last error.
    pub error: Option<String>,
}

/// Internal context holding both client and state dispatch.
#[derive(Clone)]
struct AuthContextInner {
    client: BetterAuthClient,
    state: UseStateHandle<AuthContextValue>,
}

impl PartialEq for AuthContextInner {
    fn eq(&self, other: &Self) -> bool {
        self.state == other.state
    }
}

/// Auth provider component.
///
/// Maps to React's `<AuthProvider>`.
/// Wraps children and provides the auth context.
#[derive(Properties, Clone)]
pub struct AuthProviderProps {
    pub client: BetterAuthClient,
    pub children: Children,
}

impl PartialEq for AuthProviderProps {
    fn eq(&self, other: &Self) -> bool {
        // Only compare children for re-render optimization
        self.children == other.children
    }
}

#[function_component(AuthProvider)]
pub fn auth_provider(props: &AuthProviderProps) -> Html {
    let state = use_state(|| AuthContextValue {
        session: None,
        is_loading: true,
        error: None,
    });

    let inner = AuthContextInner {
        client: props.client.clone(),
        state: state.clone(),
    };

    // Initial session fetch
    {
        let inner = inner.clone();
        use_effect_with((), move |_| {
            let inner = inner.clone();
            wasm_bindgen_futures::spawn_local(async move {
                match inner.client.get_session().await {
                    Ok(Some(data)) => {
                        inner.state.set(AuthContextValue {
                            session: Some(data),
                            is_loading: false,
                            error: None,
                        });
                    }
                    Ok(None) => {
                        inner.state.set(AuthContextValue {
                            session: None,
                            is_loading: false,
                            error: None,
                        });
                    }
                    Err(e) => {
                        inner.state.set(AuthContextValue {
                            session: None,
                            is_loading: false,
                            error: Some(e.to_string()),
                        });
                    }
                }
            });
        });
    }

    html! {
        <ContextProvider<Rc<AuthContextInner>> context={Rc::new(inner)}>
            { props.children.clone() }
        </ContextProvider<Rc<AuthContextInner>>>
    }
}

/// Hook to get the current session.
///
/// Maps to TS `client.useSession()`.
/// Returns `Option<SessionData>` that reactively updates.
#[hook]
pub fn use_session() -> Option<SessionData> {
    let ctx = use_context::<Rc<AuthContextInner>>()
        .expect("use_session must be used within an AuthProvider");
    ctx.state.session.clone()
}

/// Hook to get the loading state.
#[hook]
pub fn use_session_loading() -> bool {
    let ctx = use_context::<Rc<AuthContextInner>>()
        .expect("use_session_loading must be used within an AuthProvider");
    ctx.state.is_loading
}

/// Hook to get the error state.
#[hook]
pub fn use_session_error() -> Option<String> {
    let ctx = use_context::<Rc<AuthContextInner>>()
        .expect("use_session_error must be used within an AuthProvider");
    ctx.state.error.clone()
}

/// Hook to get the auth client for imperative operations.
#[hook]
pub fn use_auth_client() -> BetterAuthClient {
    let ctx = use_context::<Rc<AuthContextInner>>()
        .expect("use_auth_client must be used within an AuthProvider");
    ctx.client.clone()
}

/// Combined session state type.
#[derive(Clone, Debug, PartialEq)]
pub struct SessionState {
    pub data: Option<SessionData>,
    pub is_pending: bool,
    pub error: Option<String>,
}

/// Hook to get the full session state.
#[hook]
pub fn use_session_state() -> SessionState {
    let ctx = use_context::<Rc<AuthContextInner>>()
        .expect("use_session_state must be used within an AuthProvider");
    SessionState {
        data: ctx.state.session.clone(),
        is_pending: ctx.state.is_loading,
        error: ctx.state.error.clone(),
    }
}
