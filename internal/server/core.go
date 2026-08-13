package server

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/softrenzu/Keycloak/internal/policy"
	"github.com/softrenzu/Keycloak/internal/security"
	"github.com/softrenzu/Keycloak/internal/store"
)

type Server struct {
	Store                                                          *store.Store
	Signer                                                         *security.Signer
	AdminToken                                                     string
	IssuerBase                                                     string
	requests, authSuccess, authFailure, policyAllows, policyDenies atomic.Uint64
}

func New() *Server {
	admin := os.Getenv("ROOOMID_ADMIN_TOKEN")
	if admin == "" {
		admin = "dev-admin-token"
		log.Print("WARNING: using development admin token; set ROOOMID_ADMIN_TOKEN")
	}
	base := os.Getenv("ROOOMID_ISSUER_BASE")
	if base == "" {
		base = "http://localhost:8080"
	}
	s := &Server{Store: store.New(), Signer: security.NewSigner(), AdminToken: admin, IssuerBase: strings.TrimRight(base, "/")}
	s.bootstrap()
	return s
}

func (s *Server) bootstrap() {
	_, _ = s.Store.CreateTenant("demo")
	_ = s.Store.PutUser("demo", &store.User{ID: "user-alice", Username: "alice", PasswordHash: security.HashPassword("alice-password"), Roles: []string{"developer"}, Attributes: map[string]string{"department": "engineering"}})
	_ = s.Store.PutClient("demo", &store.Client{ID: "demo-app", SecretHash: security.HashPassword("demo-secret"), RedirectURIs: []string{"http://localhost:3000/callback"}, Scopes: []string{"openid", "profile", "api.read"}})
	_ = s.Store.AddPolicy("demo", store.Policy{ID: "developers-read", Effect: "allow", Priority: 100, SubjectRole: "developer", Action: "read", ResourceType: "project", MaxRisk: 70})
	_ = s.Store.AddPolicy("demo", store.Policy{ID: "suspended-deny", Effect: "deny", Priority: 1000, Action: "*", ResourceType: "*", SubjectAttributes: map[string]string{"suspended": "true"}})
	_ = s.Store.AddRelation("demo", store.Relation{SubjectID: "user-alice", Relation: "owner", ResourceType: "project", ResourceID: "alpha"})
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.health)
	mux.HandleFunc("/metrics", s.metrics)
	mux.HandleFunc("/access/v1/evaluation", s.authzen)
	mux.HandleFunc("/access/v1/explain", s.explain)
	mux.HandleFunc("/admin/", s.admin)
	mux.HandleFunc("/t/", s.tenantRoute)
	return s.middleware(mux)
}

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.requests.Add(1)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
func jsonOut(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func errOut(w http.ResponseWriter, status int, code, desc string) {
	jsonOut(w, status, map[string]any{"error": code, "error_description": desc})
}
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	jsonOut(w, 200, map[string]any{"status": "ok", "service": "RooomID", "time": time.Now().UTC()})
}
func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "rooomid_http_requests_total %d\nrooomid_auth_success_total %d\nrooomid_auth_failure_total %d\nrooomid_policy_allow_total %d\nrooomid_policy_deny_total %d\n", s.requests.Load(), s.authSuccess.Load(), s.authFailure.Load(), s.policyAllows.Load(), s.policyDenies.Load())
}
func (s *Server) audit(t, actor, action, result string, details map[string]any) {
	s.Store.Audit(store.AuditEvent{At: time.Now().UTC(), TenantID: t, Actor: actor, Action: action, Result: result, Details: details})
}
func contains(xs []string, v string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

type decisionInput struct {
	Tenant  string `json:"tenant"`
	Subject struct {
		ID         string         `json:"id"`
		Properties map[string]any `json:"properties"`
	} `json:"subject"`
	Action struct {
		Name string `json:"name"`
	} `json:"action"`
	Resource struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	} `json:"resource"`
	Context map[string]any `json:"context"`
}

func (s *Server) authzen(w http.ResponseWriter, r *http.Request) { s.evaluate(w, r, false) }
func (s *Server) explain(w http.ResponseWriter, r *http.Request) { s.evaluate(w, r, true) }
func (s *Server) evaluate(w http.ResponseWriter, r *http.Request, explain bool) {
	if r.Method != "POST" {
		errOut(w, 405, "method_not_allowed", "POST required")
		return
	}
	var in decisionInput
	if json.NewDecoder(r.Body).Decode(&in) != nil {
		errOut(w, 400, "invalid_request", "invalid json")
		return
	}
	t, ok := s.Store.SnapshotTenant(in.Tenant)
	if !ok {
		errOut(w, 404, "tenant_not_found", "unknown tenant")
		return
	}
	d := policy.Evaluate(t, policy.Request{SubjectID: in.Subject.ID, Roles: anyStrings(in.Subject.Properties["roles"]), SubjectAttributes: anyStringMap(in.Subject.Properties["attributes"]), Action: in.Action.Name, ResourceType: in.Resource.Type, ResourceID: in.Resource.ID, Risk: anyInt(in.Context["risk"]), TrustedDevice: anyBool(in.Context["trusted_device"])}, explain)
	if d.Allow {
		s.policyAllows.Add(1)
	} else {
		s.policyDenies.Add(1)
	}
	result := "deny"
	if d.Allow {
		result = "allow"
	}
	s.audit(in.Tenant, in.Subject.ID, "authorize", result, map[string]any{"reason": d.Reason})
	if explain {
		jsonOut(w, 200, d)
	} else {
		jsonOut(w, 200, map[string]any{"decision": d.Allow, "reason": d.Reason})
	}
}
func anyStrings(v any) []string {
	a, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(a))
	for _, x := range a {
		if z, ok := x.(string); ok {
			out = append(out, z)
		}
	}
	return out
}
func anyStringMap(v any) map[string]string {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	out := map[string]string{}
	for k, x := range m {
		if z, ok := x.(string); ok {
			out[k] = z
		}
	}
	return out
}
func anyInt(v any) int   { x, _ := v.(float64); return int(x) }
func anyBool(v any) bool { x, _ := v.(bool); return x }

func (s *Server) admin(w http.ResponseWriter, r *http.Request) {
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-RooomID-Admin")), []byte(s.AdminToken)) != 1 {
		errOut(w, 401, "unauthorized", "admin token required")
		return
	}
	p := strings.Split(strings.TrimPrefix(r.URL.Path, "/admin/"), "/")
	if len(p) == 1 && p[0] == "audit" {
		jsonOut(w, 200, s.Store.AuditSnapshot())
		return
	}
	if len(p) < 2 || p[0] != "tenants" {
		http.NotFound(w, r)
		return
	}
	t := p[1]
	if len(p) == 2 && r.Method == "POST" {
		if _, err := s.Store.CreateTenant(t); err != nil {
			errOut(w, 409, "conflict", err.Error())
			return
		}
		jsonOut(w, 201, map[string]any{"id": t})
		return
	}
	if len(p) != 3 || r.Method != "POST" {
		http.NotFound(w, r)
		return
	}
	switch p[2] {
	case "policies":
		var x store.Policy
		if json.NewDecoder(r.Body).Decode(&x) != nil {
			errOut(w, 400, "invalid_request", "invalid json")
			return
		}
		if err := s.Store.AddPolicy(t, x); err != nil {
			errOut(w, 404, "tenant_not_found", err.Error())
			return
		}
		jsonOut(w, 201, x)
	case "relations":
		var x store.Relation
		if json.NewDecoder(r.Body).Decode(&x) != nil {
			errOut(w, 400, "invalid_request", "invalid json")
			return
		}
		if err := s.Store.AddRelation(t, x); err != nil {
			errOut(w, 404, "tenant_not_found", err.Error())
			return
		}
		jsonOut(w, 201, x)
	default:
		http.NotFound(w, r)
	}
}

func decodeJSON(r *http.Request, v any) error { return json.NewDecoder(r.Body).Decode(v) }
