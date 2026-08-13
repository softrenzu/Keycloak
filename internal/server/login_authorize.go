package server

import (
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/softrenzu/Keycloak/internal/security"
	"github.com/softrenzu/Keycloak/internal/store"
)

func (s *Server) login(w http.ResponseWriter, r *http.Request, t string) {
	if r.Method != "POST" {
		errOut(w, 405, "method_not_allowed", "POST required")
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if decodeJSON(r, &in) != nil {
		errOut(w, 400, "invalid_request", "invalid json")
		return
	}
	u, ok := s.Store.FindUserByUsername(t, in.Username)
	if !ok || u.Disabled || !security.VerifyPassword(u.PasswordHash, in.Password) {
		s.authFailure.Add(1)
		s.audit(t, in.Username, "login", "deny", nil)
		errOut(w, 401, "access_denied", "invalid credentials")
		return
	}
	tok := store.RandomToken(32)
	s.Store.PutLogin(store.LoginSession{Token: tok, TenantID: t, UserID: u.ID, ExpiresAt: time.Now().Add(10 * time.Minute)})
	s.authSuccess.Add(1)
	s.audit(t, u.ID, "login", "allow", nil)
	jsonOut(w, 200, map[string]any{"session_token": tok, "expires_in": 600})
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request, t string) {
	q := r.URL.Query()
	if q.Get("response_type") != "code" {
		errOut(w, 400, "unsupported_response_type", "only code supported")
		return
	}
	c, ok := s.Store.Client(t, q.Get("client_id"))
	if !ok {
		errOut(w, 400, "invalid_client", "unknown client")
		return
	}
	redir := q.Get("redirect_uri")
	if !contains(c.RedirectURIs, redir) {
		errOut(w, 400, "invalid_request", "redirect_uri not registered")
		return
	}
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		errOut(w, 400, "invalid_request", "PKCE S256 required")
		return
	}
	sess, ok := s.Store.ConsumeLogin(q.Get("session_token"))
	if !ok || sess.TenantID != t {
		errOut(w, 401, "login_required", "obtain session_token from /login")
		return
	}
	code := store.RandomToken(32)
	s.Store.PutCode(store.AuthCode{Code: code, TenantID: t, ClientID: c.ID, UserID: sess.UserID, RedirectURI: redir, Scopes: strings.Fields(q.Get("scope")), CodeChallenge: q.Get("code_challenge"), ExpiresAt: time.Now().Add(2 * time.Minute)})
	u, _ := url.Parse(redir)
	x := u.Query()
	x.Set("code", code)
	if st := q.Get("state"); st != "" {
		x.Set("state", st)
	}
	u.RawQuery = x.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}
