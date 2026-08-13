# Security Policy

RooomID is alpha software. It is intended for evaluation and development, not yet for protecting production identities.

## Implemented safeguards

- Ed25519 signatures for JWTs.
- Salted iterative SHA-256 password and client-secret KDF with 250,000 rounds for the dependency-free alpha.
- Mandatory PKCE S256 for authorization codes.
- One-time authorization codes.
- Refresh-token rotation and reuse detection.
- Exact redirect URI matching.
- Default-deny authorization with explicit-deny precedence.
- Tenant-specific issuer construction and checks in delegated token exchange.
- Security response headers and bounded HTTP server timeouts.

## Production blockers

Before production use, replace the alpha KDF with Argon2id, scrypt, or bcrypt after security review; replace the in-memory store with a durable transactional store; persist and rotate signing keys instead of generating them at process start; add standard UserInfo, introspection, and revocation endpoints; move administrator authentication to a privileged identity flow; add rate limiting, browser CSRF protections where applicable, protocol conformance tests, fuzzing, independent threat modeling, penetration testing, and a vulnerability disclosure process.

Never deploy development defaults unchanged.
