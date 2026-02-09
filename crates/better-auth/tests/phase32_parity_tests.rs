//! Phase 32 — Comprehensive parity tests.
//!
//! Covers gaps vs the 74 TS test files. ~100 new tests for:
//! sign-up, sign-in, sign-out, session, password, update-user, account,
//! error codes, crypto, OAuth state, handler types, URL utils, context, trusted origins.

// ═══════════════════ 32A: Sign-up ═══════════════════

#[cfg(test)]
mod sign_up_tests {
    use better_auth::routes::sign_up::*;

    #[test]
    fn deser_minimal() {
        let r: SignUpRequest = serde_json::from_str(r#"{"email":"a@b.com","password":"s","name":"A"}"#).unwrap();
        assert_eq!(r.email, "a@b.com");
        assert!(r.image.is_none());
    }

    #[test]
    fn deser_full() {
        let r: SignUpRequest = serde_json::from_str(
            r#"{"email":"a@b.com","password":"p","name":"A","image":"i.png","callbackUrl":"/c","rememberMe":false}"#
        ).unwrap();
        assert_eq!(r.image.as_deref(), Some("i.png"));
        assert_eq!(r.callback_url.as_deref(), Some("/c"));
        assert_eq!(r.remember_me, Some(false));
    }

    #[test]
    fn deser_missing_required() {
        assert!(serde_json::from_str::<SignUpRequest>(r#"{"email":"a@b.com"}"#).is_err());
    }

    #[test]
    fn deser_additional_fields() {
        let r: SignUpRequest = serde_json::from_str(
            r#"{"email":"a@b.com","password":"p","name":"A","custom":"v"}"#
        ).unwrap();
        assert_eq!(r.additional_fields.get("custom").unwrap(), "v");
    }

    #[test]
    fn response_ser() {
        let j = serde_json::to_value(SignUpResponse {
            user: serde_json::json!({"id":"u1"}), token: Some("t".into()),
        }).unwrap();
        assert_eq!(j["user"]["id"], "u1");
        assert_eq!(j["token"], "t");
    }

    #[test]
    fn response_no_token() {
        let j = serde_json::to_value(SignUpResponse {
            user: serde_json::json!({}), token: None,
        }).unwrap();
        assert!(j["token"].is_null());
    }

    #[test]
    fn error_display() {
        assert!(format!("{}", SignUpError::UserAlreadyExists).contains("already"));
        assert!(format!("{}", SignUpError::InvalidEmail).contains("Invalid"));
        assert!(format!("{}", SignUpError::PasswordTooShort).contains("short"));
        assert!(format!("{}", SignUpError::PasswordTooLong).contains("long"));
    }

    #[test]
    fn handler_error_display() {
        let e = SignUpHandlerError::BadRequest(SignUpError::InvalidEmail);
        assert!(format!("{}", e).contains("Invalid"));
        let e = SignUpHandlerError::Internal("boom".into());
        assert!(format!("{}", e).contains("boom"));
    }
}

// ═══════════════════ 32A: Sign-in ═══════════════════

#[cfg(test)]
mod sign_in_tests {
    use better_auth::routes::sign_in::*;

    #[test]
    fn deser_minimal() {
        let r: SignInRequest = serde_json::from_str(r#"{"email":"u@t.com","password":"p"}"#).unwrap();
        assert_eq!(r.email, "u@t.com");
        assert!(r.remember_me.is_none());
    }

    #[test]
    fn deser_full() {
        let r: SignInRequest = serde_json::from_str(
            r#"{"email":"u@t.com","password":"p","rememberMe":true,"callbackUrl":"/d"}"#
        ).unwrap();
        assert_eq!(r.remember_me, Some(true));
        assert_eq!(r.callback_url.as_deref(), Some("/d"));
    }

    #[test]
    fn response_ser() {
        let j = serde_json::to_value(SignInResponse {
            user: serde_json::json!({"id":"u1"}),
            session: serde_json::json!({"id":"s1"}),
            token: "t".into(), redirect: None, url: None,
        }).unwrap();
        assert_eq!(j["token"], "t");
    }

    #[test]
    fn response_with_redirect() {
        let j = serde_json::to_value(SignInResponse {
            user: serde_json::json!({}), session: serde_json::json!({}),
            token: "t".into(), redirect: Some(true), url: Some("https://x.com".into()),
        }).unwrap();
        assert_eq!(j["redirect"], true);
        assert_eq!(j["url"], "https://x.com");
    }

    #[test]
    fn error_display() {
        assert!(!format!("{}", SignInError::InvalidEmailOrPassword).is_empty());
        assert!(!format!("{}", SignInError::EmailNotVerified).is_empty());
    }

    #[test]
    fn social_deser() {
        let r: SocialSignInRequest = serde_json::from_str(r#"{"provider":"google"}"#).unwrap();
        assert_eq!(r.provider, "google");
        assert!(r.callback_url.is_none());
        assert!(r.disable_redirect.is_none());
    }
}

// ═══════════════════ 32B: Session ═══════════════════

#[cfg(test)]
mod session_tests {
    use better_auth::routes::session::*;
    use chrono::{TimeDelta, Utc};

    #[test]
    fn resp_no_refresh() {
        let j = serde_json::to_value(SessionResponse {
            session: serde_json::json!({"id":"s"}),
            user: serde_json::json!({"id":"u"}),
            needs_refresh: None,
        }).unwrap();
        assert!(j.get("needsRefresh").is_none());
    }

    #[test]
    fn resp_with_refresh() {
        let j = serde_json::to_value(SessionResponse {
            session: serde_json::json!({}), user: serde_json::json!({}),
            needs_refresh: Some(true),
        }).unwrap();
        assert_eq!(j["needsRefresh"], true);
    }

    #[test]
    fn fresh_disabled() { assert!(is_session_fresh(&serde_json::json!({}), 0)); }

    #[test]
    fn fresh_recent() {
        assert!(is_session_fresh(&serde_json::json!({"updatedAt": Utc::now().to_rfc3339()}), 300));
    }

    #[test]
    fn fresh_stale() {
        let old = Utc::now() - TimeDelta::seconds(600);
        assert!(!is_session_fresh(&serde_json::json!({"updatedAt": old.to_rfc3339()}), 300));
    }

    #[test]
    fn fresh_missing() {
        assert!(!is_session_fresh(&serde_json::json!({"id":"s"}), 300));
    }

    #[test]
    fn opts_default() {
        let d = GetSessionOptions::default();
        assert!(!d.is_post);
        assert!(!d.dont_remember_me);
    }

    #[test]
    fn result_fields() {
        let r = GetSessionResult {
            response: None,
            set_session_cookie: None,
            delete_session_cookie: false,
            expire_session_data_cookie: false,
        };
        assert!(r.response.is_none());
        assert!(!r.delete_session_cookie);
    }
}

// ═══════════════════ 32C: Password ═══════════════════

#[cfg(test)]
mod password_tests {
    use better_auth::routes::password::*;

    #[test]
    fn forgot_deser() {
        let r: ForgotPasswordRequest = serde_json::from_str(r#"{"email":"u@t.com","redirectTo":"/r"}"#).unwrap();
        assert_eq!(r.email, "u@t.com");
        assert_eq!(r.redirect_to.as_deref(), Some("/r"));
    }

    #[test]
    fn forgot_minimal() {
        let r: ForgotPasswordRequest = serde_json::from_str(r#"{"email":"u@t.com"}"#).unwrap();
        assert!(r.redirect_to.is_none());
    }

    #[test]
    fn reset_deser() {
        let r: ResetPasswordRequest = serde_json::from_str(r#"{"token":"t","newPassword":"np"}"#).unwrap();
        assert_eq!(r.token, "t");
        assert_eq!(r.new_password, "np");
    }

    #[test]
    fn status_resp() {
        let j = serde_json::to_value(PasswordStatusResponse { status: true, message: Some("ok".into()) }).unwrap();
        assert_eq!(j["status"], true);
        assert_eq!(j["message"], "ok");
    }

    #[test]
    fn verify_deser() {
        let r: VerifyPasswordRequest = serde_json::from_str(r#"{"password":"p"}"#).unwrap();
        assert_eq!(r.password, "p");
    }
}

// ═══════════════════ 32C: Update-user ═══════════════════

#[cfg(test)]
mod update_user_tests {
    use better_auth::routes::update_user::*;

    #[test]
    fn update_deser() {
        let r: UpdateUserRequest = serde_json::from_str(r#"{"name":"N"}"#).unwrap();
        assert_eq!(r.name.as_deref(), Some("N"));
    }

    #[test]
    fn change_pw_deser() {
        let r: ChangePasswordRequest = serde_json::from_str(
            r#"{"currentPassword":"o","newPassword":"n","revokeOtherSessions":true}"#
        ).unwrap();
        assert_eq!(r.current_password, "o");
        assert_eq!(r.revoke_other_sessions, Some(true));
    }

    #[test]
    fn set_pw_deser() {
        let r: SetPasswordRequest = serde_json::from_str(r#"{"newPassword":"n"}"#).unwrap();
        assert_eq!(r.new_password, "n");
    }

    #[test]
    fn email_deser() {
        let r: ChangeEmailRequest = serde_json::from_str(r#"{"newEmail":"n@t.com"}"#).unwrap();
        assert_eq!(r.new_email, "n@t.com");
    }

    #[test]
    fn delete_deser() {
        let r: DeleteUserRequest = serde_json::from_str(r#"{"password":"p"}"#).unwrap();
        assert_eq!(r.password.as_deref(), Some("p"));
    }

    #[test]
    fn update_resp() {
        assert_eq!(serde_json::to_value(UpdateUserResponse { status: true }).unwrap()["status"], true);
    }

    #[test]
    fn delete_resp() {
        let j = serde_json::to_value(DeleteUserResponse { success: true, message: "ok".into() }).unwrap();
        assert_eq!(j["success"], true);
    }
}

// ═══════════════════ 32D: Account ═══════════════════

#[cfg(test)]
mod account_tests {
    use better_auth::routes::account::*;

    #[test]
    fn unlink_deser() {
        let r: UnlinkAccountRequest = serde_json::from_str(r#"{"providerId":"google"}"#).unwrap();
        assert_eq!(r.provider_id, "google");
    }

    #[test]
    fn unlink_error_display() {
        assert!(!format!("{}", UnlinkError::AccountNotFound).is_empty());
        assert!(!format!("{}", UnlinkError::LastAccount).is_empty());
    }

    #[test]
    fn refresh_deser() {
        let r: RefreshTokenRequest = serde_json::from_str(r#"{"providerId":"gh"}"#).unwrap();
        assert_eq!(r.provider_id, "gh");
    }

    #[test]
    fn status_resp() {
        assert_eq!(serde_json::to_value(StatusResponse { status: true }).unwrap()["status"], true);
    }

    #[test]
    fn delete_account_deser() {
        let r: DeleteAccountRequest = serde_json::from_str(r#"{"password":"p","callbackUrl":"/c"}"#).unwrap();
        assert_eq!(r.password.as_deref(), Some("p"));
        assert_eq!(r.callback_url.as_deref(), Some("/c"));
    }
}

// ═══════════════════ 32D: Error codes ═══════════════════

#[cfg(test)]
mod error_tests {
    use better_auth::routes::error::*;

    #[test]
    fn code_details() {
        let (s, c, m) = ErrorCode::UserNotFound.details();
        assert_eq!(s, 404);
        assert_eq!(c, "USER_NOT_FOUND");
        assert!(!m.is_empty());
    }

    #[test]
    fn code_statuses() {
        assert_eq!(ErrorCode::Unauthorized.details().0, 401);
        assert_eq!(ErrorCode::UserAlreadyExists.details().0, 409);
        assert_eq!(ErrorCode::InternalServerError.details().0, 500);
        assert_eq!(ErrorCode::RateLimitExceeded.details().0, 429);
        assert_eq!(ErrorCode::InvalidPassword.details().0, 400);
    }

    #[test]
    fn api_error_constructors() {
        assert_eq!(ApiError::unauthorized("x").status, 401);
        assert_eq!(ApiError::forbidden("x").status, 403);
        assert_eq!(ApiError::not_found("x").status, 404);
        assert_eq!(ApiError::bad_request("x").status, 400);
        assert_eq!(ApiError::internal("x").status, 500);
        assert_eq!(ApiError::too_many_requests("x").status, 429);
    }

    #[test]
    fn api_error_from_code() {
        let e = ApiError::from_code(ErrorCode::Unauthorized);
        assert_eq!(e.status, 401);
        assert!(!e.message.is_empty());
    }

    #[test]
    fn api_error_response_ser() {
        let j = serde_json::to_value(
            ApiErrorResponse::new("fail").with_code("ERR").with_status(400)
        ).unwrap();
        assert_eq!(j["message"], "fail");
        assert_eq!(j["code"], "ERR");
        assert_eq!(j["status"], 400);
    }

    #[test]
    fn test_render_error_page() {
        let html = better_auth::routes::error::render_error_page("ACCESS_DENIED", Some("No access"));
        assert!(html.contains("ACCESS_DENIED"));
        assert!(html.contains("<html"));
    }

    #[test]
    fn test_render_error_page_no_desc() {
        let html = better_auth::routes::error::render_error_page("UNKNOWN", None);
        assert!(html.contains("UNKNOWN"));
    }
}

// ═══════════════════ 32F: Crypto - Password ═══════════════════

#[cfg(test)]
mod crypto_password_tests {
    use better_auth::crypto::password::*;

    #[test]
    fn hash_produces_output() { assert!(!hash_password("mySecurePassword123!").unwrap().is_empty()); }

    #[test]
    fn verify_correct() {
        let h = hash_password("correct").unwrap();
        assert!(verify_password(&h, "correct").unwrap());
    }

    #[test]
    fn verify_incorrect() {
        let h = hash_password("correct").unwrap();
        assert!(!verify_password(&h, "wrong").unwrap());
    }

    #[test]
    fn different_hashes() {
        assert_ne!(hash_password("same").unwrap(), hash_password("same").unwrap());
    }

    #[test]
    fn case_sensitive() {
        let h = hash_password("CaseSensitive").unwrap();
        assert!(!verify_password(&h, "casesensitive").unwrap());
        assert!(!verify_password(&h, "CASESENSITIVE").unwrap());
    }

    #[test]
    fn long_password() {
        let p = "a".repeat(1000);
        assert!(verify_password(&hash_password(&p).unwrap(), &p).unwrap());
    }

    #[test]
    fn unicode_password() {
        let p = "пароль123!";
        assert!(verify_password(&hash_password(p).unwrap(), p).unwrap());
    }

    #[test]
    fn special_chars() {
        let p = r#"!@#$%^&*()_+-={}[]|\":;'<>,.?/~`"#;
        assert!(verify_password(&hash_password(p).unwrap(), p).unwrap());
    }
}

// ═══════════════════ 32F: Crypto - Symmetric ═══════════════════

#[cfg(test)]
mod crypto_symmetric_tests {
    use better_auth::crypto::symmetric::*;

    #[test]
    fn roundtrip() {
        let e = symmetric_encrypt("k", "Hello").unwrap();
        assert_eq!(symmetric_decrypt("k", &e).unwrap(), "Hello");
    }

    #[test]
    fn different_ciphertexts() {
        assert_ne!(symmetric_encrypt("k", "d").unwrap(), symmetric_encrypt("k", "d").unwrap());
    }

    #[test]
    fn wrong_key() {
        assert!(symmetric_decrypt("wrong", &symmetric_encrypt("right", "d").unwrap()).is_err());
    }

    #[test]
    fn empty_data() {
        let e = symmetric_encrypt("k", "").unwrap();
        assert_eq!(symmetric_decrypt("k", &e).unwrap(), "");
    }

    #[test]
    fn large_payload() {
        let d = "x".repeat(10_000);
        assert_eq!(symmetric_decrypt("k", &symmetric_encrypt("k", &d).unwrap()).unwrap(), d);
    }

    #[test]
    fn signature_roundtrip() {
        let s = make_signature("hello", "secret").unwrap();
        assert!(verify_signature("hello", "secret", &s).unwrap());
    }

    #[test]
    fn signature_wrong_secret() {
        let s = make_signature("hello", "secret").unwrap();
        assert!(!verify_signature("hello", "wrong", &s).unwrap());
    }

    #[test]
    fn const_time_eq() {
        assert!(constant_time_equal(b"abc", b"abc"));
        assert!(!constant_time_equal(b"abc", b"xyz"));
        assert!(!constant_time_equal(b"abc", b"ab"));
    }
}

// ═══════════════════ 32F: Crypto - Random ═══════════════════

#[cfg(test)]
mod crypto_random_tests {
    use better_auth::crypto::random::*;

    #[test]
    fn lengths() {
        for l in [8, 16, 32, 64, 128] { assert_eq!(generate_random_string(l).len(), l); }
    }

    #[test]
    fn unique() { assert_ne!(generate_random_string(32), generate_random_string(32)); }

    #[test]
    fn valid_chars() {
        let s = generate_random_string(100);
        assert!(s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'));
    }
}

// ═══════════════════ 32G: OAuth State ═══════════════════

#[cfg(test)]
mod oauth_state_tests {
    use better_auth::oauth::state::*;

    #[test]
    fn state_data_serde() {
        let sd = StateData {
            callback_url: "/cb".into(),
            code_verifier: "cv".into(),
            error_url: None,
            new_user_url: None,
            expires_at: 9999999999,
            link: None,
            request_sign_up: Some(false),
        };
        let json = serde_json::to_string(&sd).unwrap();
        let sd2: StateData = serde_json::from_str(&json).unwrap();
        assert_eq!(sd2.callback_url, "/cb");
        assert_eq!(sd2.code_verifier, "cv");
        assert_eq!(sd2.request_sign_up, Some(false));
    }

    #[test]
    fn state_error_code_display() {
        let d = format!("{}", StateErrorCode::Invalid);
        assert!(d.contains("invalid"));
    }

    #[test]
    fn generated_state() {
        let gs = GeneratedState { state: "enc".into(), code_verifier: "cv".into() };
        assert_eq!(gs.state, "enc");
        assert_eq!(gs.code_verifier, "cv");
    }
}

// ═══════════════════ 32H: Handler Types ═══════════════════

#[cfg(test)]
mod handler_tests {
    use better_auth::handler::*;
    use std::collections::HashMap;

    #[test]
    fn req_get() {
        let r = GenericRequest { method: "GET".into(), path: "/session".into(), query: None, headers: HashMap::new(), body: None };
        assert_eq!(r.method, "GET");
    }

    #[test]
    fn req_post_header() {
        let mut h = HashMap::new();
        h.insert("content-type".into(), "application/json".into());
        let r = GenericRequest { method: "POST".into(), path: "/t".into(), query: None, headers: h, body: Some(b"{}".to_vec()) };
        assert_eq!(r.header("content-type"), Some("application/json"));
    }

    #[test]
    fn req_json_parse() {
        let r = GenericRequest { method: "POST".into(), path: "/t".into(), query: None, headers: HashMap::new(), body: Some(br#"{"k":"v"}"#.to_vec()) };
        let v: serde_json::Value = r.json().unwrap();
        assert_eq!(v["k"], "v");
    }

    #[test]
    fn resp_json() {
        let r = GenericResponse::json(200, &serde_json::json!({"ok":true}));
        assert_eq!(r.status, 200);
        assert!(!r.body.is_empty());
    }

    #[test]
    fn resp_redirect() {
        let r = GenericResponse::redirect(302, "https://x.com/cb");
        assert_eq!(r.status, 302);
        assert_eq!(r.headers.get("location").unwrap(), &vec!["https://x.com/cb".to_string()]);
    }

    #[test]
    fn resp_error() {
        let r = GenericResponse::error(401, "UNAUTH", "nope");
        assert_eq!(r.status, 401);
        let body_str = String::from_utf8_lossy(&r.body);
        assert!(body_str.contains("UNAUTH"));
    }

    #[test]
    fn resp_html() {
        let r = GenericResponse::html(200, "<h1>Hi</h1>");
        assert_eq!(r.status, 200);
        assert!(String::from_utf8_lossy(&r.body).contains("<h1>"));
    }

    #[test]
    fn query_params() {
        let r = GenericRequest { method: "GET".into(), path: "/t".into(), query: Some("a=1&b=hi".into()), headers: HashMap::new(), body: None };
        let p = r.query_params();
        assert_eq!(p.get("a").unwrap(), "1");
        assert_eq!(p.get("b").unwrap(), "hi");
    }

    #[test]
    fn client_ip_forwarded() {
        let mut h = HashMap::new();
        h.insert("x-forwarded-for".into(), "1.2.3.4".into());
        let r = GenericRequest { method: "GET".into(), path: "/t".into(), query: None, headers: h, body: None };
        assert_eq!(r.client_ip(), "1.2.3.4");
    }
}

// ═══════════════════ 32H: URL Utilities ═══════════════════

#[cfg(test)]
mod url_tests {
    use better_auth::utils::url::*;

    #[test]
    fn has_path_yes() { assert!(has_path("https://x.com/api").unwrap()); }
    #[test]
    fn has_path_no() { assert!(!has_path("https://x.com").unwrap()); }
    #[test]
    fn has_path_slash() { assert!(!has_path("https://x.com/").unwrap()); }
    #[test]
    fn with_path_appends() { assert_eq!(with_path("https://x.com", "/api").unwrap(), "https://x.com/api"); }
    #[test]
    fn with_path_existing() { assert_eq!(with_path("https://x.com/e", "/api").unwrap(), "https://x.com/e"); }
    #[test]
    fn base_url() { assert_eq!(get_base_url(Some("https://x.com"), None).unwrap(), "https://x.com/api/auth"); }
    #[test]
    fn base_url_custom() { assert_eq!(get_base_url(Some("https://x.com"), Some("/a")).unwrap(), "https://x.com/a"); }
    #[test]
    fn origin() { assert_eq!(get_origin("https://x.com/p"), Some("https://x.com".into())); }
    #[test]
    fn origin_invalid() { assert_eq!(get_origin("invalid"), None); }
    #[test]
    fn host_with_port() { assert_eq!(get_host("https://x.com:8080/p"), Some("x.com:8080".into())); }
    #[test]
    fn proxy_proto() {
        assert!(validate_proxy_header("https", ProxyHeaderType::Proto));
        assert!(!validate_proxy_header("ftp", ProxyHeaderType::Proto));
    }
    #[test]
    fn proxy_host() {
        assert!(validate_proxy_header("example.com", ProxyHeaderType::Host));
        assert!(!validate_proxy_header("../evil", ProxyHeaderType::Host));
    }
}

// ═══════════════════ 32H: Trusted Origins ═══════════════════

#[cfg(test)]
mod trusted_origin_tests {
    use better_auth::middleware::trusted_origins::*;

    #[test]
    fn exact_match() { assert!(is_trusted_origin("https://x.com", &["https://x.com".into()], false)); }
    #[test]
    fn no_match() { assert!(!is_trusted_origin("https://evil.com", &["https://x.com".into()], false)); }
    #[test]
    fn wildcard() { assert!(matches_origin_pattern("https://sub.x.com", "https://*.x.com", false)); }
    #[test]
    fn relative() { assert!(matches_origin_pattern("/cb", "/cb", true)); }
    #[test]
    fn empty_list() { assert!(!is_trusted_origin("https://x.com", &[], false)); }
}

// ═══════════════════ 32: Init ═══════════════════

#[cfg(test)]
mod init_tests {
    use better_auth::init::*;

    #[test]
    fn validate_secret_short() { assert!(!validate_secret("short").is_empty()); }

    #[test]
    fn validate_secret_good() {
        let w = validate_secret("this-is-a-sufficiently-long-secret-key-for-production");
        assert!(w.is_empty() || w.len() <= 1);
    }
}
