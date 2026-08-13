# RooomID

RooomID is an experimental open-source identity and authorization server for modern APIs, SaaS, workloads, and AI agents. It is designed as a small authorization-first alternative to traditional IAM servers.

> **Status: alpha.** Runnable and locally tested, but not production-hardened. A broader feature direction does not imply greater security maturity than Keycloak.

## What is different

- RBAC, ABAC, and ReBAC in one decision engine.
- AuthZEN-style decision API plus a deterministic explain endpoint.
- Request-risk and trusted-device inputs for continuous authorization.
- AI agent/workload identity using Client Credentials and delegated Token Exchange with `act` claims.
- Tenant-scoped issuers and data boundaries.
- Mandatory PKCE S256 for Authorization Code flows.
- Ed25519/EdDSA JWT signing and JWKS discovery.
- Refresh-token rotation with reuse detection.
- Audit events and Prometheus-compatible metrics.
- One Go binary with zero third-party Go dependencies.

## Alpha capability matrix

| Capability | Status |
|---|---|
| OIDC discovery | Implemented |
| Authorization Code + PKCE S256 | Implemented |
| Client Credentials | Implemented |
| Refresh Token rotation | Implemented |
| RFC 8693-style Token Exchange | Implemented |
| EdDSA JWT + JWKS | Implemented |
| RBAC / ABAC / ReBAC | Implemented |
| AuthZEN-style evaluation | Implemented |
| Explainable policy traces | Implemented |
| Risk/device context | Implemented |
| Multi-tenancy | Implemented |
| Policy / relation admin API | Implemented |
| Prometheus metrics | Implemented |
| UserInfo / introspection / revocation endpoint | Roadmap |
| SAML / WebAuthn / SCIM / LDAP | Roadmap |
| Persistent SQL store / HA | Roadmap |
| Admin UI | Roadmap |

## Run

```bash
go run ./cmd/rooomid
```

Configuration is provided through `ROOOMID_ADDR`, `ROOOMID_ISSUER_BASE`, and `ROOOMID_ADMIN_TOKEN`. The source includes a development-only demo tenant for local evaluation. Replace all development defaults before any deployment.

### Authorization decision

```bash
curl -s http://localhost:8080/access/v1/evaluation \
  -H 'content-type: application/json' \
  -d '{
    "tenant":"demo",
    "subject":{"id":"user-alice","properties":{"roles":["developer"]}},
    "action":{"name":"read"},
    "resource":{"type":"project","id":"alpha"},
    "context":{"risk":10,"trusted_device":true}
  }'
```

Send the same request to `/access/v1/explain` to receive the policy trace.

### Relationship-aware policy

```json
{
  "id": "project-owner-write",
  "effect": "allow",
  "priority": 200,
  "action": "write",
  "resource_type": "project",
  "relation": "owner",
  "max_risk": 50,
  "require_trusted_device": true
}
```

Policies can be added at `/admin/tenants/{tenant}/policies` and relationship tuples at `/admin/tenants/{tenant}/relations` using the configured administrator token.

## Validate

```bash
go test ./...
go vet ./...
go build ./cmd/rooomid
```

See `docs/ARCHITECTURE.md` and `SECURITY.md` before extending or deploying RooomID.

## License

MIT License. See `LICENSE`.
