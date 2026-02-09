# Plugins Reference

This document provides a detailed reference for all 27 plugins available in BetterRustAuth.

## Enabling Plugins

Plugins are feature-gated in your `Cargo.toml`:

```toml
[dependencies]
better-auth = { version = "0.1", features = ["plugin-two-factor", "plugin-admin"] }
```

## Plugin List

### access

**Feature flag:** `plugin-access`

Role-Based Access Control (RBAC) with declarative permission rules.

**Key Endpoints:**
- Uses middleware to check permissions on protected routes

**Options:**
- `roles` — Define roles and their permissions
- `default_role` — Role assigned to new users

---

### additional-fields

**Feature flag:** `plugin-additional-fields`

Extend user and session schemas with custom fields at runtime.

**Options:**
- `user_fields` — Additional fields for the user table
- `session_fields` — Additional fields for the session table

---

### admin

**Feature flag:** `plugin-admin`

Full administrative CRUD operations for user management.

**Key Endpoints:**
- `POST /admin/create-user` — Create user as admin
- `POST /admin/set-role` — Set user role
- `POST /admin/ban-user` — Ban a user
- `POST /admin/unban-user` — Unban a user
- `POST /admin/impersonate-user` — Impersonate a user
- `POST /admin/stop-impersonating` — Stop impersonation
- `GET /admin/list-users` — List all users with pagination
- `POST /admin/remove-user` — Remove a user
- `POST /admin/revoke-user-session` — Revoke a specific user's session
- `POST /admin/revoke-user-sessions` — Revoke all sessions for a user

---

### anonymous

**Feature flag:** `plugin-anonymous`

Create anonymous sessions that can later be linked to a real account.

**Key Endpoints:**
- `POST /sign-in/anonymous` — Create anonymous session
- `POST /anonymous/link-account` — Link anonymous session to real user

---

### api-key

**Feature flag:** `plugin-api-key`

API key generation, validation, rotation, and permission scoping.

**Key Endpoints:**
- `POST /api-key/create` — Generate a new API key
- `GET /api-key/list` — List all API keys for user
- `POST /api-key/revoke` — Revoke an API key
- `POST /api-key/rotate` — Rotate (regenerate) an API key
- `GET /api-key/verify` — Verify an API key

**Options:**
- `key_prefix` — Custom prefix for generated keys
- `rate_limit` — Per-key rate limiting
- `default_permissions` — Default permissions for new keys

---

### bearer

**Feature flag:** `plugin-bearer`

Use Bearer tokens (from `Authorization: Bearer <token>`) instead of cookies for session management. Ideal for API-first applications.

---

### captcha

**Feature flag:** `plugin-captcha`

Verify captcha tokens before allowing sign-up or sign-in.

**Supported Providers:**
- Cloudflare Turnstile
- Google reCAPTCHA v2 and v3
- hCaptcha

**Options:**
- `provider` — Which captcha provider to use
- `secret_key` — Server-side verification secret
- `endpoints` — Which endpoints require captcha verification

---

### custom-session

**Feature flag:** `plugin-custom-session`

Store arbitrary custom data in sessions.

**Options:**
- `fields` — Custom field definitions to add to the session model

---

### device-authorization

**Feature flag:** `plugin-device-authorization`

OAuth 2.0 Device Authorization Grant (RFC 8628) for input-constrained devices.

**Key Endpoints:**
- `POST /device-authorization/authorize` — Start device authorization
- `POST /device-authorization/verify` — User verifies the device code
- `POST /device-authorization/token` — Device polls for token

---

### email-otp

**Feature flag:** `plugin-email-otp`

Email-based one-time passwords for passwordless authentication.

**Key Endpoints:**
- `POST /email-otp/send-verification-otp` — Send OTP to email
- `POST /email-otp/verify-email` — Verify OTP
- `POST /email-otp/sign-in` — Sign in with OTP

**Options:**
- `otp_length` — Length of generated OTP (default: 6)
- `expires_in` — OTP expiry in seconds (default: 300)
- `send_verification_otp` — Async callback to actually send the OTP email

---

### generic-oauth

**Feature flag:** `plugin-generic-oauth`

Register custom OAuth providers not included in the built-in 33.

**Options:**
- `providers` — Array of custom provider configurations with authorization/token endpoints

---

### haveibeenpwned

**Feature flag:** `plugin-haveibeenpwned`

Check passwords against the HaveIBeenPwned database during sign-up.

**Options:**
- `threshold` — Minimum breach count to reject (default: 1)

---

### jwt

**Feature flag:** `plugin-jwt`

Issue JWT session tokens instead of opaque tokens. Useful for stateless session validation.

**Key Endpoints:**
- `GET /jwt/get-token` — Get JWT for current session

---

### last-login-method

**Feature flag:** `plugin-last-login-method`

Track and store the authentication method used for the most recent login.

---

### magic-link

**Feature flag:** `plugin-magic-link`

Passwordless authentication via email magic links.

**Key Endpoints:**
- `POST /magic-link/send` — Send magic link email
- `GET /magic-link/verify` — Verify magic link token

---

### mcp

**Feature flag:** `plugin-mcp`

Model Context Protocol authentication support for AI/LLM integrations.

---

### multi-session

**Feature flag:** `plugin-multi-session`

Allow users to have multiple active sessions simultaneously, with the ability to switch between them.

**Key Endpoints:**
- `POST /multi-session/set-active` — Switch active session
- `GET /multi-session/list-device-sessions` — List sessions on this device

---

### oauth-proxy

**Feature flag:** `plugin-oauth-proxy`

Proxy OAuth flows for client-side applications that can't safely store client secrets.

---

### oidc-provider

**Feature flag:** `plugin-oidc-provider`

Turn your auth server into a full OpenID Connect provider.

**Key Endpoints:**
- `GET /.well-known/openid-configuration` — OIDC discovery
- `POST /oidc/authorize` — Authorization endpoint
- `POST /oidc/token` — Token endpoint
- `GET /oidc/userinfo` — UserInfo endpoint
- `GET /oidc/jwks` — JSON Web Key Set
- `POST /oidc/register` — Dynamic client registration

---

### one-tap

**Feature flag:** `plugin-one-tap`

Google One Tap sign-in integration with ID token verification.

**Key Endpoints:**
- `POST /one-tap/callback` — Handle One Tap credential response

---

### one-time-token

**Feature flag:** `plugin-one-time-token`

Generate and verify secure, single-use tokens for cross-system authentication.

**Key Endpoints:**
- `POST /one-time-token/generate` — Generate a one-time token
- `POST /one-time-token/verify` — Verify and consume a token

---

### open-api

**Feature flag:** `plugin-open-api`

Generate OpenAPI/Swagger specification for all registered endpoints.

**Key Endpoints:**
- `GET /reference` — OpenAPI spec as JSON

---

### organization

**Feature flag:** `plugin-organization`

Multi-tenant organization management with teams, roles, members, and invitations.

**Key Endpoints (30+):**
- `POST /organization/create` — Create organization
- `POST /organization/update` — Update organization
- `POST /organization/delete` — Delete organization
- `POST /organization/invite-member` — Invite a member
- `POST /organization/accept-invitation` — Accept invitation
- `POST /organization/reject-invitation` — Reject invitation
- `POST /organization/cancel-invitation` — Cancel invitation
- `POST /organization/remove-member` — Remove member
- `POST /organization/update-member-role` — Change member role
- `GET /organization/list` — List user's organizations
- `GET /organization/get-full` — Get organization with members
- `POST /organization/set-active` — Set active organization
- `POST /organization/create-team` — Create a team
- `POST /organization/add-team-member` — Add member to team
- `POST /organization/remove-team-member` — Remove from team
- `GET /organization/list-teams` — List teams
- `POST /organization/has-permission` — Check permission

---

### phone-number

**Feature flag:** `plugin-phone-number`

Phone number verification with SMS OTP.

**Key Endpoints:**
- `POST /phone-number/send-otp` — Send OTP via SMS
- `POST /phone-number/verify` — Verify phone OTP
- `POST /phone-number/remove` — Remove phone number

**Options:**
- `otp_length` — Length of generated OTP (default: 6)
- `expires_in` — OTP expiry in seconds
- `send_otp` — Async callback to actually send the SMS

---

### siwe (Sign-In with Ethereum)

**Feature flag:** `plugin-siwe`

Authenticate with Ethereum wallets using EIP-4361.

**Key Endpoints:**
- `POST /siwe/get-nonce` — Get a nonce for signing
- `POST /siwe/verify` — Verify signed message

**Crypto Implementation:**
- secp256k1 ECDSA signature recovery via `k256` crate
- EIP-191 message hashing with Keccak-256
- Ethereum address derivation from recovered public key

---

### two-factor

**Feature flag:** `plugin-two-factor`

Time-based One-Time Password (TOTP) with backup codes.

**Key Endpoints:**
- `POST /two-factor/enable` — Enable 2FA (returns QR code URI)
- `POST /two-factor/disable` — Disable 2FA
- `POST /two-factor/verify` — Verify TOTP code
- `POST /two-factor/generate-backup-codes` — Generate backup codes
- `POST /two-factor/verify-backup-code` — Verify backup code

---

### username

**Feature flag:** `plugin-username`

Add username-based authentication alongside email.

**Key Endpoints:**
- `POST /sign-in/username` — Sign in with username/password
