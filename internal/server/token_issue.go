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
	requested := strings.Fields(r.FormValue("scope"))
	if len(requested) == 0 {
		requested = append([]string(nil), c.Scopes...)
	}
	if !scopeSubset(requested, c.Scopes) {
		errOut(w, 400, "invalid_scope", "requested scope exceeds client grants")
		return
	}
	claims := map[string]any{"sub": c.ID, "client_id": c.ID, "token_use": "access", "roles": []string{"workload"}}
	tok, _ := s.makeToken(t, c.ID, "", requested, claims, 15*time.Minute)
	jsonOut(w, 200, map[string]any{"access_token": tok, "token_type": "Bearer", "expires_in": 900, "scope": strings.Join(requested, " ")})
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
	if use, _ := subject["token_use"].(string); use != "access" {
		errOut(w, 400, "invalid_grant", "only access tokens can be delegated")
		return
	}
	jti, _ := subject["jti"].(string)
	record, ok := s.Store.Token(jti)
	if !ok || record.Revoked || record.TenantID != t || time.Now().After(record.ExpiresAt) {
		errOut(w, 400, "invalid_grant", "subject token revoked or unknown")
		return
	}

	parentScopes := strings.Fields(stringClaim(subject, "scope"))
	requested := strings.Fields(r.FormValue("scope"))
	if len(requested) == 0 {
		requested = intersectScopes(parentScopes, c.Scopes)
	}
	if !scopeSubset(requested, parentScopes) || !scopeSubset(requested, c.Scopes) {
		errOut(w, 400, "invalid_scope", "delegated scope must be a subset of both subject and client grants")
		return
	}

	audience := r.FormValue("audience")
	if audience == "" {
		audience = c.ID
	}
	if audience != c.ID {
		errOut(w, 400, "invalid_target", "audience must match the authenticated client")
		return
	}

	sub, _ := subject["sub"].(string)
	claims := map[string]any{
		"sub":            sub,
		"client_id":      c.ID,
		"act":            map[string]any{"sub": c.ID},
		"delegated_from": sub,
		"token_use":      "access",
		"aud":            audience,
	}
	tok, _ := s.makeToken(t, c.ID, sub, requested, claims, 15*time.Minute)
	s.audit(t, sub, "token_exchange", "allow", map[string]any{"client_id": c.ID, "scope": requested, "audience": audience})
	jsonOut(w, 200, map[string]any{
		"access_token":      tok,
		"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
		"token_type":         "Bearer",
		"expires_in":         900,
		"scope":              strings.Join(requested, " "),
	})
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

func stringClaim(claims map[string]any, key string) string {
	v, _ := claims[key].(string)
	return v
}

func scopeSubset(requested, allowed []string) bool {
	set := make(map[string]struct{}, len(allowed))
	for _, s := range allowed {
		set[s] = struct{}{}
	}
	for _, s := range requested {
		if _, ok := set[s]; !ok {
			return false
		}
	}
	return true
}

func intersectScopes(a, b []string) []string {
	set := make(map[string]struct{}, len(b))
	for _, s := range b {
		set[s] = struct{}{}
	}
	out := make([]string, 0)
	seen := map[string]struct{}{}
	for _, s := range a {
		if _, ok := set[s]; !ok {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
