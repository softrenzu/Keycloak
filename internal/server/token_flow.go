package server

import (
	"net/http"

	"github.com/softrenzu/Keycloak/internal/security"
	"github.com/softrenzu/Keycloak/internal/store"
)

func (s *Server) clientAuth(r *http.Request, t string) (*store.Client, bool) {
	id, pw, ok := r.BasicAuth()
	if !ok {
		id = r.FormValue("client_id")
		pw = r.FormValue("client_secret")
	}
	c, ok := s.Store.Client(t, id)
	if !ok {
		return nil, false
	}
	if c.Public {
		return c, true
	}
	return c, security.VerifyPassword(c.SecretHash, pw)
}

func (s *Server) token(w http.ResponseWriter, r *http.Request, t string) {
	if r.Method != "POST" {
		errOut(w, 405, "method_not_allowed", "POST required")
		return
	}
	_ = r.ParseForm()
	switch r.FormValue("grant_type") {
	case "authorization_code":
		s.exchangeCode(w, r, t)
	case "refresh_token":
		s.refresh(w, r, t)
	case "client_credentials":
		s.clientCredentials(w, r, t)
	case "urn:ietf:params:oauth:grant-type:token-exchange":
		s.tokenExchange(w, r, t)
	default:
		errOut(w, 400, "unsupported_grant_type", "unsupported grant")
	}
}

func (s *Server) exchangeCode(w http.ResponseWriter, r *http.Request, t string) {
	c, ok := s.clientAuth(r, t)
	if !ok {
		errOut(w, 401, "invalid_client", "client authentication failed")
		return
	}
	code, ok := s.Store.ConsumeCode(r.FormValue("code"))
	if !ok || code.TenantID != t || code.ClientID != c.ID || code.RedirectURI != r.FormValue("redirect_uri") || security.S256(r.FormValue("code_verifier")) != code.CodeChallenge {
		errOut(w, 400, "invalid_grant", "code or PKCE validation failed")
		return
	}
	s.issueUserTokens(w, t, c.ID, code.UserID, code.Scopes)
}

func (s *Server) refresh(w http.ResponseWriter, r *http.Request, t string) {
	c, ok := s.clientAuth(r, t)
	if !ok {
		errOut(w, 401, "invalid_client", "client authentication failed")
		return
	}
	x, rt, err := s.Store.RotateRefresh(r.FormValue("refresh_token"))
	if err != nil || x.TenantID != t || x.ClientID != c.ID {
		errOut(w, 400, "invalid_grant", "refresh token invalid or reused")
		return
	}
	s.issueUserTokensWithRefresh(w, t, c.ID, x.UserID, x.Scopes, rt)
}
