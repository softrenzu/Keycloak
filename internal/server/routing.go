package server

import (
	"net/http"
	"net/url"
	"strings"
)

func (s *Server) tenantRoute(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) < 3 || parts[0] != "t" {
		http.NotFound(w, r)
		return
	}
	t := parts[1]
	path := "/" + strings.Join(parts[2:], "/")
	if _, ok := s.Store.Tenant(t); !ok {
		errOut(w, 404, "tenant_not_found", "unknown tenant")
		return
	}
	switch path {
	case "/.well-known/openid-configuration":
		s.discovery(w, r, t)
	case "/oauth2/jwks":
		jsonOut(w, 200, s.Signer.JWKS())
	case "/login":
		s.login(w, r, t)
	case "/oauth2/authorize":
		s.authorize(w, r, t)
	case "/oauth2/token":
		s.token(w, r, t)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) issuer(t string) string { return s.IssuerBase + "/t/" + url.PathEscape(t) }

func (s *Server) discovery(w http.ResponseWriter, r *http.Request, t string) {
	iss := s.issuer(t)
	jsonOut(w, 200, map[string]any{
		"issuer": iss,
		"authorization_endpoint": iss + "/oauth2/authorize",
		"token_endpoint": iss + "/oauth2/token",
		"jwks_uri": iss + "/oauth2/jwks",
		"response_types_supported": []string{"code"},
		"grant_types_supported": []string{"authorization_code", "refresh_token", "client_credentials", "urn:ietf:params:oauth:grant-type:token-exchange"},
		"code_challenge_methods_supported": []string{"S256"},
		"id_token_signing_alg_values_supported": []string{"EdDSA"},
	})
}
