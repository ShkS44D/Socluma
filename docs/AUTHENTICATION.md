# TriageOps Authentication Architecture

## Design

Interactive users authenticate with a short-lived JWT access token and an opaque refresh token. Only an HMAC hash of each refresh token is stored. Refresh tokens rotate on use and belong to a database-backed session/family. Reuse of a rotated token revokes that family. Individual revocation and logout-all invalidate the session and its complete refresh chain. Collector bearer authentication remains separate and does not use interactive MFA.

TOTP follows the standard 30-second, six-digit SHA-1 profile used by common authenticator apps, with issuer `TriageOps` and a one-step clock tolerance. Secrets are encrypted using the application encryption service. Enrollment secrets expire and become active only after confirmation. The last accepted time step prevents replay. Recovery codes are random, displayed once, HMAC-hashed at rest, and consumed once.

Email-verification and password-reset links contain random, expiring, single-use values. Only HMAC hashes are stored. Request endpoints give generic responses. Existing users are migration-exempt from mandatory verification so enabling the production requirement does not unexpectedly lock them out.

## API flows

- `POST /api/v1/auth/login`: returns the normal token pair, or `mfa_required` plus a five-minute challenge.
- `POST /api/v1/auth/mfa/complete`: consumes the challenge with a TOTP or recovery code and creates the session.
- `/api/v1/account/security/mfa/*`: enroll, confirm, disable, and regenerate recovery codes.
- `/api/v1/auth/email-verification/{request,confirm}`: request and consume verification links.
- `/api/v1/auth/password-reset/{request,complete}`: request and complete password reset.
- `/api/v1/account/security/sessions`: paginated session history and individual revocation.
- `/api/v1/account/security/events`: paginated, user- and tenant-scoped security history.

Authentication responses use `Cache-Control: no-store`. Stable errors include `MFA_REQUIRED`, `MFA_INVALID`, `MFA_LOCKED`, `EMAIL_NOT_VERIFIED`, `TOKEN_INVALID`, `TOKEN_EXPIRED`, `SESSION_NOT_FOUND`, `SESSION_REVOKED`, `RATE_LIMITED`, and `ACCOUNT_LOCKED`.

## Email and production setup

Set `FRONTEND_PUBLIC_URL` to the HTTPS browser origin. Configure `SMTP_HOST`, port, TLS, username/password when required, and a safe `AUTH_EMAIL_FROM`. Set `AUTH_EMAIL_CAPTURE=false`, `AUTH_DEV_EXPOSE_TOKENS=false`, `SECURE_COOKIE=true`, and use Redis-backed rate limiting in production. `EMAIL_VERIFICATION_REQUIRED=true` requires working SMTP. Captured email is only for local tests.

## Security events

Security history records UTC time, event/result/severity, safe IP/user-agent/device labels, reason codes, and request IDs. Deterministic suspicious signals include unseen devices/IPs, failures before success, rapid multi-IP sessions, repeated MFA failure, and refresh-token reuse. It does not claim geolocation or impossible-travel detection.

## Compatibility and limitations

The React client still stores bearer access and refresh tokens through the existing browser-storage abstraction to preserve API, collector, and integration compatibility. A future transport migration should move browser refresh tokens to scoped HttpOnly secure cookies with CSRF protection. Phase 2 does not implement SSO, SAML, OIDC enterprise login, SCIM, CAPTCHA, GeoIP, or compromised-password-provider checks.
