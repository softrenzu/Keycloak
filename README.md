# RooomID

RooomID is an open-source identity and authorization server built for applications, workloads, and AI agents.

The design goal is to go beyond classic IAM by making authentication, fine-grained authorization, relationship-aware access control, contextual risk, policy explanation, and delegated agent identity part of one control plane.

> Status: alpha / developer preview. RooomID is runnable and testable, but it is not yet a drop-in replacement for a mature Keycloak production deployment.

## Why RooomID

Keycloak is a mature identity platform with OIDC, SAML, passkeys, organizations, SCIM, FAPI 2, DPoP, AuthZEN work, and token-exchange capabilities. RooomID deliberately does not try to win by cloning every Keycloak screen. It focuses on areas where modern application and AI-agent authorization benefits from a more unified model.

| Area | RooomID approach |
|---|---|
| Authentication | Multi-tenant OAuth/OIDC-style authorization code flow with mandatory PKCE S256 |
| Workload identity | OAuth client credentials with registered-scope enforcement |
| Agent delegation | OAuth token exchange with dual down-scoping against both subject and client grants |
| Authorization | RBAC + ABAC + ReBAC in one policy engine |
| Adaptive access | Risk threshold and trusted-device conditions are first-class policy inputs |
| Explainability | Decision-trace endpoint for policy debugging |
| External PDP | AuthZEN-shaped `/access/v1/evaluation` API |
| Token crypto | Ed25519 signatures and JWKS publishing |
| Password storage | Versioned PBKDF2-HMAC-SHA256 hashes |
| Audit/metrics | In-process audit trail plus Prometheus text metrics |

## Implemented today

- Tenant-isolated identity, clients, roles, policies, relationships, sessions and audit events
- Authorization Code flow with PKCE S256
- Client Credentials flow
- Refresh token rotation with reuse detection
- OAuth 2.0 Token Exchange for workload/agent delegation
- Delegated-scope enforcement: an exchanged token cannot exceed the subject token or authenticated client's grants
- Ed25519 signed access and ID tokens
- JWKS endpoint and tenant-scoped issuer discovery
- Explicit-deny-first authorization with default deny
- RBAC, subject ABAC, resource targeting, ReBAC, max-risk and trusted-device conditions
- AuthZEN-style access evaluation endpoint
- Explainable policy trace endpoint
- Admin APIs protected by an admin token
- Health and Prometheus-format metrics endpoints

## Quick start

Requirements: Go 1.23+.

```bash
export ROOOMID_ADMIN_TOKEN='replace-with-a-long-random-secret'
export ROOOMID_ISSUER_BASE='http://localhost:8080'
go run ./cmd/rooomid
```

Or with Docker:

```bash
ROOOMID_ADMIN_TOKEN='replace-with-a-long-random-secret' docker compose up --build
```

Health check:

```bash
curl http://localhost:8080/healthz
```

## Demo tenant

The alpha bootstrap creates:

- tenant: `demo`
- user: `alice`
- password: `alice-password`
- client: `demo-app`
- client secret: `demo-secret`
- redirect URI: `http://localhost:3000/callback`

These values are for local development only. Do not deploy the bootstrap credentials to a networked production environment.

### 1. Login

```bash
SESSION=$(curl -s http://localhost:8080/t/demo/login \
  -H 'content-type: application/json' \
  -d '{"username":"alice","password":"alice-password"}')
```

### 2. Authorization + PKCE

Generate a verifier and S256 challenge in your OAuth client, then call:

```text
GET /t/demo/oauth2/authorize?response_type=code&client_id=demo-app&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&scope=openid%20profile%20api.read&code_challenge=...&code_challenge_method=S256&session_token=...
```

Exchange the returned code at `/t/demo/oauth2/token` using `grant_type=authorization_code`, the exact redirect URI, and the original PKCE verifier.

## AuthZEN-style policy decision

```bash
curl -s http://localhost:8080/access/v1/evaluation \
  -H 'content-type: application/json' \
  -d '{
    "tenant":"demo",
    "subject":{"id":"user-alice","properties":{"roles":["developer"],"attributes":{"department":"engineering"}}},
    "action":{"name":"read"},
    "resource":{"type":"project","id":"alpha"},
    "context":{"risk":20,"trusted_device":true}
  }'
```

For a decision trace, send the same payload to:

```text
POST /access/v1/explain
```

The engine evaluates explicit denies first, then allows, and otherwise returns default deny.

## Agent/workload delegation

RooomID supports OAuth token exchange:

```text
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
subject_token=<USER_OR_WORKLOAD_ACCESS_TOKEN>
scope=api.read
audience=demo-app
```

Delegation is intentionally constrained:

1. the subject token must be a live RooomID access token;
2. it must not be revoked;
3. requested scopes must be a subset of the subject token scopes;
4. requested scopes must also be a subset of the authenticated client's grants;
5. the requested audience must match the authenticated client in the alpha implementation.

This prevents a delegated AI agent from silently minting broader permissions than either side already possesses.

## Authorization model

A policy can combine:

- role requirements (RBAC)
- subject attributes (ABAC)
- resource type and resource ID
- direct relationships (ReBAC)
- maximum accepted risk
- trusted-device requirement
- explicit allow or explicit deny
- priority ordering

Example conceptually:

```json
{
  "id": "project-read",
  "effect": "allow",
  "subject_role": "developer",
  "action": "read",
  "resource_type": "project",
  "relation": "member",
  "max_risk": 50,
  "require_trusted_device": true
}
```

## Admin API

Set `ROOOMID_ADMIN_TOKEN` and pass it using the alpha admin header:

```text
X-RooomID-Admin: <token>
```

Current admin routes include tenant creation, policy creation, relationship creation, and audit retrieval. The admin API is intentionally minimal while the authorization surface stabilizes.

## Repository layout

```text
cmd/rooomid/          server entrypoint
internal/security/    JWT, JWKS, PKCE and password hashing
internal/store/       in-memory tenant/session/token/audit store
internal/policy/      unified RBAC/ABAC/ReBAC/risk evaluator
internal/server/      OAuth, AuthZEN-style PDP and admin HTTP APIs
docs/                 architecture and security notes
```

## Production roadmap

RooomID is not yet feature-parity with Keycloak. Production work still includes:

- persistent SQL storage and migrations
- persistent/rotating signing keys with KMS/HSM support
- WebAuthn/passkeys and MFA/step-up flows
- SAML 2.0
- LDAP/Active Directory federation
- SCIM 2.0 provisioning
- DPoP and FAPI 2 conformance
- full OIDC/OAuth conformance testing
- multi-node cache/session coordination and HA
- rate limiting, abuse controls and lockout policy
- richer organization/delegated administration
- admin web console
- external security review and threat-model validation

## Development

```bash
go test ./...
go vet ./...
go build ./cmd/rooomid
```

## License

Apache License 2.0. See `LICENSE`.
