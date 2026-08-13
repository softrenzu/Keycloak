package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/softrenzu/Keycloak/internal/security"
	"github.com/softrenzu/Keycloak/internal/store"
)

type Server struct {
	Store *store.Store
	Signer *security.Signer
	AdminToken string
	IssuerBase string
	requests, authSuccess, authFailure, policyAllows, policyDenies atomic.Uint64
}
func New()*Server{admin:=os.Getenv("ROOOMID_ADMIN_TOKEN");if admin==""{admin="dev-admin-token";log.Print("WARNING: using development admin token; set ROOOMID_ADMIN_TOKEN")};base:=os.Getenv("ROOOMID_ISSUER_BASE");if base==""{base="http://localhost:8080"};s:=&Server{Store:store.New(),Signer:security.NewSigner(),AdminToken:admin,IssuerBase:strings.TrimRight(base,"/")};s.bootstrap();return s}
func (s *Server) bootstrap(){_,_=s.Store.CreateTenant("demo");_=s.Store.PutUser("demo",&store.User{ID:"user-alice",Username:"alice",PasswordHash:security.HashPassword("alice-password"),Roles:[]string{"developer"},Attributes:map[string]string{"department":"engineering"}});_=s.Store.PutClient("demo",&store.Client{ID:"demo-app",SecretHash:security.HashPassword("demo-secret"),RedirectURIs:[]string{"http://localhost:3000/callback"},Scopes:[]string{"openid","profile","api.read"}});_=s.Store.AddPolicy("demo",store.Policy{ID:"developers-read",Effect:"allow",Priority:100,SubjectRole:"developer",Action:"read",ResourceType:"project",MaxRisk:70});_=s.Store.AddPolicy("demo",store.Policy{ID:"suspended-deny",Effect:"deny",Priority:1000,Action:"*",ResourceType:"*",SubjectAttributes:map[string]string{"suspended":"true"}});_=s.Store.AddRelation("demo",store.Relation{SubjectID:"user-alice",Relation:"owner",ResourceType:"project",ResourceID:"alpha"})}
func (s *Server) Handler()http.Handler{mux:=http.NewServeMux();mux.HandleFunc("/healthz",s.health);mux.HandleFunc("/metrics",s.metrics);mux.HandleFunc("/access/v1/evaluation",s.authzen);mux.HandleFunc("/access/v1/explain",s.explain);mux.HandleFunc("/admin/",s.admin);mux.HandleFunc("/t/",s.tenantRoute);return s.middleware(mux)}
func (s *Server) middleware(next http.Handler)http.Handler{return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){s.requests.Add(1);w.Header().Set("X-Content-Type-Options","nosniff");w.Header().Set("Referrer-Policy","no-referrer");w.Header().Set("Cache-Control","no-store");next.ServeHTTP(w,r)})}
func jsonOut(w http.ResponseWriter,status int,v any){w.Header().Set("Content-Type","application/json");w.WriteHeader(status);_=json.NewEncoder(w).Encode(v)}
func errOut(w http.ResponseWriter,status int,code,desc string){jsonOut(w,status,map[string]any{"error":code,"error_description":desc})}
func (s *Server) health(w http.ResponseWriter,r *http.Request){jsonOut(w,200,map[string]any{"status":"ok","service":"RooomID","time":time.Now().UTC()})}
func (s *Server) metrics(w http.ResponseWriter,r *http.Request){w.Header().Set("Content-Type","text/plain; version=0.0.4");fmt.Fprintf(w,"rooomid_http_requests_total %d\nrooomid_auth_success_total %d\nrooomid_auth_failure_total %d\nrooomid_policy_allow_total %d\nrooomid_policy_deny_total %d\n",s.requests.Load(),s.authSuccess.Load(),s.authFailure.Load(),s.policyAllows.Load(),s.policyDenies.Load())}
func (s *Server) audit(t,actor,action,result string,details map[string]any){s.Store.Audit(store.AuditEvent{At:time.Now().UTC(),TenantID:t,Actor:actor,Action:action,Result:result,Details:details})}
func contains(xs []string,v string)bool{for _,x:=range xs{if x==v{return true}};return false}
