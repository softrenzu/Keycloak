# RooomID Architecture

RooomID separates identity issuance from authorization decisions while shipping both in one small process for the alpha release.

## Request planes

- Identity plane: `/t/{tenant}/...` for OIDC/OAuth2 login, authorization, token issuance, token exchange, and JWKS.
- Authorization plane: `/access/v1/evaluation` and `/access/v1/explain`.
- Administration plane: `/admin/tenants/{tenant}/...` for tenant, policy, and relationship management.
- Operations plane: `/healthz` and `/metrics`.

## Unified authorization model

A decision receives a subject, action, resource, and request context. Policies can combine roles (RBAC), subject attributes (ABAC), subject-resource relationships (ReBAC), risk ceilings, and trusted-device requirements. Policies are priority ordered. Any matching deny terminates evaluation. At least one allow must match; otherwise the result is default deny.

The explain endpoint uses the same deterministic evaluator and returns per-policy match traces. It does not rely on an LLM.

## Agent and workload identity

Machine identities use Client Credentials. Delegation uses Token Exchange and emits an `act` claim containing the requesting client identity, keeping the original subject distinct from the workload acting for that subject.

## Tenant boundary

Each tenant owns independent users, OAuth clients, policies, relationship tuples, codes, and sessions. Tenant identifiers are included in issuer paths so token and policy scope can be kept separate.

## Alpha storage

The alpha uses a concurrency-safe in-memory store to keep the implementation small and auditable. Authorization codes are single use. Refresh tokens rotate and reused tokens are rejected. Audit events are retained in a bounded in-memory log.

## Production evolution

The next production milestone should add PostgreSQL-backed transactional storage, encrypted signing-key persistence and rotation, cluster-safe sessions, UserInfo/introspection/revocation, passkeys/WebAuthn, SCIM, LDAP/AD federation, SAML, and browser administration/login interfaces.
