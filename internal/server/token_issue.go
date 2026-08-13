package server

import (
	"net/http"
	"strings"
	"time"

	"github.com/softrenzu/Keycloak/internal/store"
)

func (s *Server) clientCredentials(w http.ResponseWriter, r *http.Request, t string) {
	c, ok := s.clientAuth(r, t)
	if !ok {
		errOut(w, 401, "invalid_client", "client authentication failed")
		return
	}
	claims := map[string]any{"sub": c.ID, "client_id": c.ID, "token_use": "access", "roles": []string{"workload"}}
	tok, _ := s.makeToken(t, c.ID, "", strings.Fields(r.FormValue("scope")), claims, 15*time.Minute)
	jsonOut(w, 200, map[string]any{"access_token": tok, "token_type": "Bearer", "expires_in": 900})
}

func (s *Server) tokenExchange(w http.ResponseWriter, r *http.Request, t string) {
	c, ok := s.clientAuth(r, t)
	if !ok {
		errOut(w, 401, "invalid_client", "client authentication failed")
		return
	}
	subject, err := s.Signer.Verify(r.FormValue("subject_token"))
	if err != nil {
		errOut(w, 400, "invalid_grant", "subject token invalid")
		return
	}
	if iss, _ := subject["iss"].(string); iss != s.issuer(t) {
		errOut(w, 400, "invalid_grant", "issuer mismatch")
		return
	}
	sub, _ := subject["sub"].(string)
	claims := map[string]any{"sub": sub, "client_id": c.ID, "act": map[string]any{"sub": c.ID}, "delegated_from": sub, "token_use": "access"}
	if aud := r.FormValue("audience"); aud != "" {
		claims["aud"] = aud
	}
	tok, _ := s.makeToken(t, c.ID, sub, strings.Fields(r.FormValue("scope")), claims, 15*time.Minute)
	jsonOut(w, 200, map[string]any{"access_token": tok, "issued_token_type": "urn:ietf:params:oauth:token-type:access_token", "token_type": "Bearer", "expires_in": 900})
}

func (s *Server) issueUserTokens(w http.ResponseWriter, t, client, user string, scopes []string) {
	rt := store.RandomToken(32)
	s.Store.PutRefresh(&store.RefreshSession{Token: rt, TenantID: t, ClientID: client, UserID: user, Scopes: scopes, ExpiresAt: time.Now().Add(24 * time.Hour)})
	s.issueUserTokensWithRefresh(w, t, client, user, scopes, rt)
}

func (s *Server) issueUserTokensWithRefresh(w http.ResponseWriter, t, client, user string, scopes []string, rt string) {
	u, ok := s.Store.User(t, user)
	if !ok || u.Disabled {
		errOut(w, 401, "invalid_grant", "user disabled")
		return
	}
	access, _ := s.makeToken(t, client, u.ID, scopes, map[string]any{"sub": u.ID, "preferred_username": u.Username, "roles": u.Roles, "attributes": u.Attributes, "client_id": client, "token_use": "access"}, 15*time.Minute)
	id, _ := s.makeToken(t, client, u.ID, scopes, map[string]any{"sub": u.ID, "preferred_username": u.Username, "client_id": client, "token_use": "id"}, 15*time.Minute)
	s.authSuccess.Add(1)
	jsonOut(w, 200, map[string]any{"access_token": access, "id_token": id, "refresh_token": rt, "token_type": "Bearer", "expires_in": 900, "scope": strings.Join(scopes, " ")})
}

func (s *Server) makeToken(t, client, user string, scopes []string, c map[string]any, d time.Duration) (string, map[string]any) {
	now := time.Now().Unix()
	jti := store.RandomToken(16)
	c["iss"] = s.issuer(t)
	c["iat"] = now
	c["exp"] = now + int64(d.Seconds())
	c["jti"] = jti
	c["scope"] = strings.Join(scopes, " ")
	if _, ok := c["aud"]; !ok {
		c["aud"] = client
	}
	tok, _ := s.Signer.Sign(c)
	s.Store.PutToken(&store.TokenRecord{JTI: jti, TenantID: t, ClientID: client, UserID: user, ExpiresAt: time.Now().Add(d)})
	return tok, c
}
