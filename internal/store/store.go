package store

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sort"
	"sync"
	"time"
)

type User struct { ID string `json:"id"`; Username string `json:"username"`; PasswordHash string `json:"-"`; Roles []string `json:"roles"`; Attributes map[string]string `json:"attributes,omitempty"`; Disabled bool `json:"disabled"` }
type Client struct { ID string `json:"id"`; SecretHash string `json:"-"`; Public bool `json:"public"`; RedirectURIs []string `json:"redirect_uris"`; Scopes []string `json:"scopes"` }
type Policy struct { ID string `json:"id"`; Effect string `json:"effect"`; Priority int `json:"priority"`; SubjectRole string `json:"subject_role,omitempty"`; SubjectAttributes map[string]string `json:"subject_attributes,omitempty"`; Action string `json:"action,omitempty"`; ResourceType string `json:"resource_type,omitempty"`; ResourceID string `json:"resource_id,omitempty"`; Relation string `json:"relation,omitempty"`; MaxRisk int `json:"max_risk,omitempty"`; RequireTrustedDevice bool `json:"require_trusted_device,omitempty"` }
type Relation struct { SubjectID string `json:"subject_id"`; Relation string `json:"relation"`; ResourceType string `json:"resource_type"`; ResourceID string `json:"resource_id"` }
type Tenant struct { ID string `json:"id"`; Users map[string]*User `json:"users"`; Clients map[string]*Client `json:"clients"`; Policies []Policy `json:"policies"`; Relations []Relation `json:"relations"` }
type LoginSession struct { Token, TenantID, UserID string; ExpiresAt time.Time }
type AuthCode struct { Code, TenantID, ClientID, UserID, RedirectURI string; Scopes []string; CodeChallenge string; ExpiresAt time.Time }
type RefreshSession struct { Token, TenantID, ClientID, UserID string; Scopes []string; ExpiresAt time.Time; Revoked, Used bool }
type TokenRecord struct { JTI, TenantID, ClientID, UserID string; ExpiresAt time.Time; Revoked bool }
type AuditEvent struct { At time.Time `json:"at"`; TenantID string `json:"tenant_id,omitempty"`; Actor string `json:"actor,omitempty"`; Action string `json:"action"`; Result string `json:"result"`; Details map[string]any `json:"details,omitempty"` }

type Store struct { mu sync.RWMutex; Tenants map[string]*Tenant; Logins map[string]LoginSession; Codes map[string]AuthCode; Refresh map[string]*RefreshSession; Tokens map[string]*TokenRecord; AuditLog []AuditEvent }
func New()*Store{return &Store{Tenants:map[string]*Tenant{},Logins:map[string]LoginSession{},Codes:map[string]AuthCode{},Refresh:map[string]*RefreshSession{},Tokens:map[string]*TokenRecord{}}}
func RandomToken(n int)string{b:=make([]byte,n);_,_=rand.Read(b);return base64.RawURLEncoding.EncodeToString(b)}
func (s *Store) CreateTenant(id string)(*Tenant,error){s.mu.Lock();defer s.mu.Unlock();if _,ok:=s.Tenants[id];ok{return nil,errors.New("tenant exists")};t:=&Tenant{ID:id,Users:map[string]*User{},Clients:map[string]*Client{}};s.Tenants[id]=t;return t,nil}
func (s *Store) Tenant(id string)(*Tenant,bool){s.mu.RLock();defer s.mu.RUnlock();t,ok:=s.Tenants[id];return t,ok}
func (s *Store) PutUser(t string,u *User)error{s.mu.Lock();defer s.mu.Unlock();x,ok:=s.Tenants[t];if !ok{return errors.New("tenant not found")};x.Users[u.ID]=u;return nil}
func (s *Store) FindUserByUsername(t,name string)(*User,bool){s.mu.RLock();defer s.mu.RUnlock();x,ok:=s.Tenants[t];if !ok{return nil,false};for _,u:=range x.Users{if u.Username==name{c:=*u;return &c,true}};return nil,false}
func (s *Store) User(t,id string)(*User,bool){s.mu.RLock();defer s.mu.RUnlock();x,ok:=s.Tenants[t];if !ok{return nil,false};u,ok:=x.Users[id];if !ok{return nil,false};c:=*u;return &c,true}
func (s *Store) PutClient(t string,c *Client)error{s.mu.Lock();defer s.mu.Unlock();x,ok:=s.Tenants[t];if !ok{return errors.New("tenant not found")};x.Clients[c.ID]=c;return nil}
func (s *Store) Client(t,id string)(*Client,bool){s.mu.RLock();defer s.mu.RUnlock();x,ok:=s.Tenants[t];if !ok{return nil,false};c,ok:=x.Clients[id];if !ok{return nil,false};cp:=*c;return &cp,true}
func (s *Store) AddPolicy(t string,p Policy)error{s.mu.Lock();defer s.mu.Unlock();x,ok:=s.Tenants[t];if !ok{return errors.New("tenant not found")};x.Policies=append(x.Policies,p);sort.SliceStable(x.Policies,func(i,j int)bool{return x.Policies[i].Priority>x.Policies[j].Priority});return nil}
func (s *Store) AddRelation(t string,r Relation)error{s.mu.Lock();defer s.mu.Unlock();x,ok:=s.Tenants[t];if !ok{return errors.New("tenant not found")};x.Relations=append(x.Relations,r);return nil}
func (s *Store) SnapshotTenant(id string)(*Tenant,bool){s.mu.RLock();defer s.mu.RUnlock();x,ok:=s.Tenants[id];if !ok{return nil,false};cp:=*x;cp.Policies=append([]Policy(nil),x.Policies...);cp.Relations=append([]Relation(nil),x.Relations...);return &cp,true}
func (s *Store) PutLogin(x LoginSession){s.mu.Lock();defer s.mu.Unlock();s.Logins[x.Token]=x}
func (s *Store) ConsumeLogin(tok string)(LoginSession,bool){s.mu.RLock();defer s.mu.RUnlock();x,ok:=s.Logins[tok];if !ok||time.Now().After(x.ExpiresAt){return LoginSession{},false};return x,true}
func (s *Store) PutCode(x AuthCode){s.mu.Lock();defer s.mu.Unlock();s.Codes[x.Code]=x}
func (s *Store) ConsumeCode(code string)(AuthCode,bool){s.mu.Lock();defer s.mu.Unlock();x,ok:=s.Codes[code];if !ok||time.Now().After(x.ExpiresAt){return AuthCode{},false};delete(s.Codes,code);return x,true}
func (s *Store) PutRefresh(x *RefreshSession){s.mu.Lock();defer s.mu.Unlock();s.Refresh[x.Token]=x}
func (s *Store) RotateRefresh(tok string)(*RefreshSession,string,error){s.mu.Lock();defer s.mu.Unlock();x,ok:=s.Refresh[tok];if !ok||x.Revoked||time.Now().After(x.ExpiresAt){return nil,"",errors.New("invalid refresh token")};if x.Used{x.Revoked=true;return nil,"",errors.New("refresh token reuse detected")};x.Used=true;nt:=RandomToken(32);nx:=*x;nx.Token=nt;nx.Used=false;nx.Revoked=false;s.Refresh[nt]=&nx;cp:=nx;return &cp,nt,nil}
func (s *Store) RevokeRefresh(tok string){s.mu.Lock();defer s.mu.Unlock();if x,ok:=s.Refresh[tok];ok{x.Revoked=true}}
func (s *Store) PutToken(x *TokenRecord){s.mu.Lock();defer s.mu.Unlock();s.Tokens[x.JTI]=x}
func (s *Store) Token(jti string)(*TokenRecord,bool){s.mu.RLock();defer s.mu.RUnlock();x,ok:=s.Tokens[jti];if !ok{return nil,false};cp:=*x;return &cp,true}
func (s *Store) RevokeJTI(jti string){s.mu.Lock();defer s.mu.Unlock();if x,ok:=s.Tokens[jti];ok{x.Revoked=true}}
func (s *Store) Audit(e AuditEvent){s.mu.Lock();defer s.mu.Unlock();s.AuditLog=append(s.AuditLog,e);if len(s.AuditLog)>2000{s.AuditLog=s.AuditLog[len(s.AuditLog)-2000:]}}
func (s *Store) AuditSnapshot()[]AuditEvent{s.mu.RLock();defer s.mu.RUnlock();return append([]AuditEvent(nil),s.AuditLog...)}
