# RooomGate — Identity & Authorization Gateway

Version: `0.3.0`

RooomGate is a source-available identity and authorization server for modern APIs, SaaS, workloads, and AI agents. It combines authentication with policy-driven authorization and is designed as a compact alternative to larger IAM platforms such as Keycloak.

> Status: alpha. Runnable and locally tested, but not yet production-hardened.

## Core features

- RBAC, ABAC, and ReBAC in one decision engine
- AuthZEN-style decision API with deterministic explain traces
- Request-risk and trusted-device context for continuous authorization
- AI agent and workload identity using Client Credentials and delegated Token Exchange
- Tenant-scoped issuers and data boundaries
- Mandatory PKCE S256 for Authorization Code flows
- Ed25519/EdDSA JWT signing and JWKS discovery
- Refresh-token rotation with reuse detection
- Audit events and Prometheus-compatible metrics
- Single Go binary with zero third-party Go dependencies

## Run

```bash
go run ./cmd/rooomgate
```

The legacy command directory `cmd/rooomid` and `ROOOMID_*` environment variables are retained for compatibility. New deployments should use `ROOOMGATE_ADDR`; the server falls back to `ROOOMID_ADDR` when necessary.

Example authorization decision:

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

## Validate

```bash
go test ./...
go vet ./...
go build ./cmd/rooomgate
```

See `docs/ARCHITECTURE.md` and `SECURITY.md` before extending or deploying RooomGate.

## Licensing and enterprise support

Starting with version `0.3.0`, ROOOMTECH-authored code is offered under either the PolyForm Noncommercial License 1.0.0 for uses permitted by that license, or a separate paid ROOOMTECH Commercial Software License for business/commercial-purpose uses and other uses outside the PolyForm permission.

ROOOMTECH provides commercial license agreements, paid maintenance and technical support, implementation and integration assistance, upgrades, security support, SLA options, private builds, and custom development.

Contact: `support@rooomtech.com`

PolyForm Noncommercial License 1.0.0: https://polyformproject.org/licenses/noncommercial/1.0.0

Earlier releases remain governed by the license terms published with those releases. Third-party components, if any, remain governed by their respective licenses. See `LICENSE`.
