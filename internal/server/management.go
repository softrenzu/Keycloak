package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/softrenzu/Keycloak/internal/policy"
	"github.com/softrenzu/Keycloak/internal/security"
	"github.com/softrenzu/Keycloak/internal/store"
)

type authZENSubject struct {
	Type       string         `json:"type"`
	ID         string         `json:"id"`
	Properties map[string]any `json:"properties,omitempty"`
}

type authZENResource struct {
	Type       string         `json:"type"`
	ID         string         `json:"id"`
	Properties map[string]any `json:"properties,omitempty"`
}

type authZENAction struct {
	Name       string         `json:"name"`
	Properties map[string]any `json:"properties,omitempty"`
}

type authZENRequest struct {
	Subject  authZENSubject  `json:"subject"`
	Action   authZENAction   `json:"action"`
	Resource authZENResource `json:"resource"`
	Context  map[string]any  `json:"context,omitempty"`
}

func decodeJSON(r *http.Request, dst any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

func stringProp(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	v, _ := m[key].(string)
	return v
}

func boolProp(m map[string]any, key string) bool {
	if m == nil {
		return false
	}
	v, _ := m[key].(bool)
	return v
}

func intProp(m map[string]any, key string) int {
	if m == nil {
		return 0
	}
	switch v := m[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	default:
		return 0
	}
}

func stringSliceProp(m map[string]any, key string) []string {
	if m == nil {
		return nil
	}
	if xs, ok := m[key].([]string); ok {
		return xs
	}
	raw, ok := m[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, x := range raw {
		if s, ok := x.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func stringMapProp(m map[string]any, key string) map[string]string {
	out := map[string]string{}
	if m == nil {
		return out
	}
	raw, ok := m[key].(map[string]any)
	if !ok {
		return out
	}
	for k, v := range raw {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

func (s *Server) evaluateAuthZEN(r *http.Request, explain bool) (policy.Decision, string, error) {
	var in authZENRequest
	if err := decodeJSON(r, &in); err != nil {
		return policy.Decision{}, "", err
	}
	tenant := stringProp(in.Context, "tenant_id")
	if tenant == "" {
		tenant = stringProp(in.Subject.Properties, "tenant_id")
	}
	if tenant == "" {
		tenant = r.Header.Get("X-Rooom-Tenant")
	}
	t, ok := s.Store.SnapshotTenant(tenant)
	if !ok {
		return policy.Decision{}, tenant, &tenantNotFoundError{tenant: tenant}
	}

	req := policy.Request{
		SubjectID:         in.Subject.ID,
		Roles:             stringSliceProp(in.Subject.Properties, "roles"),
		SubjectAttributes: stringMapProp(in.Subject.Properties, "attributes"),
		Action:            in.Action.Name,
		ResourceType:      in.Resource.Type,
		ResourceID:        in.Resource.ID,
		ResourceAttributes: stringMapProp(in.Resource.Properties, "attributes"),
		Risk:              intProp(in.Context, "risk"),
		TrustedDevice:     boolProp(in.Context, "trusted_device"),
	}
	return policy.Evaluate(t, req, explain), tenant, nil
}

type tenantNotFoundError struct{ tenant string }

func (e *tenantNotFoundError) Error() string { return "tenant not found: " + e.tenant }

func (s *Server) authzen(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errOut(w, 405, "method_not_allowed", "POST required")
		return
	}
	d, tenant, err := s.evaluateAuthZEN(r, false)
	if err != nil {
		errOut(w, 400, "invalid_request", err.Error())
		return
	}
	if d.Allow {
		s.policyAllows.Add(1)
	} else {
		s.policyDenies.Add(1)
	}
	s.audit(tenant, "authzen", "authorize", map[bool]string{true: "allow", false: "deny"}[d.Allow], map[string]any{"reason": d.Reason})
	jsonOut(w, 200, map[string]any{"decision": d.Allow})
}

func (s *Server) explain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		errOut(w, 405, "method_not_allowed", "POST required")
		return
	}
	d, _, err := s.evaluateAuthZEN(r, true)
	if err != nil {
		errOut(w, 400, "invalid_request", err.Error())
		return
	}
	jsonOut(w, 200, d)
}

func (s *Server) isAdmin(r *http.Request) bool {
	return subtleBearerEqual(r.Header.Get("Authorization"), "Bearer "+s.AdminToken)
}

func subtleBearerEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := 0; i < len(a); i++ {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func (s *Server) admin(w http.ResponseWriter, r *http.Request) {
	if !s.isAdmin(r) {
		errOut(w, 401, "unauthorized", "admin bearer token required")
		return
	}
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin/"), "/")
	if path == "audit" && r.Method == http.MethodGet {
		jsonOut(w, 200, map[string]any{"events": s.Store.AuditSnapshot()})
		return
	}
	if path == "tenants" && r.Method == http.MethodPost {
		var in struct{ ID string `json:"id"` }
		if decodeJSON(r, &in) != nil || in.ID == "" {
			errOut(w, 400, "invalid_request", "id required")
			return
		}
		t, err := s.Store.CreateTenant(in.ID)
		if err != nil {
			errOut(w, 409, "conflict", err.Error())
			return
		}
		jsonOut(w, 201, t)
		return
	}
	parts := strings.Split(path, "/")
	if len(parts) != 3 || parts[0] != "tenants" {
		http.NotFound(w, r)
		return
	}
	tenant, kind := parts[1], parts[2]
	switch kind {
	case "users":
		if r.Method != http.MethodPost {
			errOut(w, 405, "method_not_allowed", "POST required")
			return
		}
		var in struct {
			ID         string            `json:"id"`
			Username   string            `json:"username"`
			Password   string            `json:"password"`
			Roles      []string          `json:"roles"`
			Attributes map[string]string `json:"attributes,omitempty"`
		}
		if decodeJSON(r, &in) != nil || in.ID == "" || in.Username == "" || len(in.Password) < 12 {
			errOut(w, 400, "invalid_request", "id, username and password (12+ chars) required")
			return
		}
		u := &store.User{ID: in.ID, Username: in.Username, PasswordHash: security.HashPassword(in.Password), Roles: in.Roles, Attributes: in.Attributes}
		if err := s.Store.PutUser(tenant, u); err != nil {
			errOut(w, 400, "invalid_request", err.Error())
			return
		}
		jsonOut(w, 201, u)
	case "policies":
		if r.Method != http.MethodPost {
			errOut(w, 405, "method_not_allowed", "POST required")
			return
		}
		var p store.Policy
		if decodeJSON(r, &p) != nil || p.ID == "" || (p.Effect != "allow" && p.Effect != "deny") {
			errOut(w, 400, "invalid_request", "valid policy required")
			return
		}
		if err := s.Store.AddPolicy(tenant, p); err != nil {
			errOut(w, 400, "invalid_request", err.Error())
			return
		}
		jsonOut(w, 201, p)
	case "relations":
		if r.Method != http.MethodPost {
			errOut(w, 405, "method_not_allowed", "POST required")
			return
		}
		var rel store.Relation
		if decodeJSON(r, &rel) != nil || rel.SubjectID == "" || rel.Relation == "" || rel.ResourceType == "" || rel.ResourceID == "" {
			errOut(w, 400, "invalid_request", "valid relation required")
			return
		}
		if err := s.Store.AddRelation(tenant, rel); err != nil {
			errOut(w, 400, "invalid_request", err.Error())
			return
		}
		jsonOut(w, 201, rel)
	default:
		http.NotFound(w, r)
	}
}
