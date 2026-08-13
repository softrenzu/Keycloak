package policy

import (
	"fmt"
	"github.com/softrenzu/Keycloak/internal/store"
	"slices"
)

type Request struct {
	SubjectID string `json:"subject_id"`
	Roles []string `json:"roles,omitempty"`
	SubjectAttributes map[string]string `json:"subject_attributes,omitempty"`
	Action string `json:"action"`
	ResourceType string `json:"resource_type"`
	ResourceID string `json:"resource_id"`
	ResourceAttributes map[string]string `json:"resource_attributes,omitempty"`
	Risk int `json:"risk,omitempty"`
	TrustedDevice bool `json:"trusted_device,omitempty"`
}

type Trace struct { PolicyID string `json:"policy_id"`; Matched bool `json:"matched"`; Effect string `json:"effect,omitempty"`; Reasons []string `json:"reasons"` }
type Decision struct { Allow bool `json:"allow"`; Reason string `json:"reason"`; Trace []Trace `json:"trace,omitempty"` }

func Evaluate(t *store.Tenant, r Request, explain bool) Decision {
	traces := []Trace{}
	allowMatched := false
	for _, p := range t.Policies {
		matched, reasons := match(t, p, r)
		tr := Trace{PolicyID: p.ID, Matched: matched, Reasons: reasons}
		if matched { tr.Effect = p.Effect }
		if explain { traces = append(traces, tr) }
		if !matched { continue }
		if p.Effect == "deny" { return Decision{Allow:false, Reason:"explicit deny by "+p.ID, Trace:traces} }
		if p.Effect == "allow" { allowMatched = true }
	}
	if allowMatched { return Decision{Allow:true, Reason:"allowed by policy", Trace:traces} }
	return Decision{Allow:false, Reason:"default deny", Trace:traces}
}

func match(t *store.Tenant, p store.Policy, r Request) (bool, []string) {
	if p.Action != "" && p.Action != "*" && p.Action != r.Action { return false, []string{"action mismatch"} }
	if p.ResourceType != "" && p.ResourceType != "*" && p.ResourceType != r.ResourceType { return false, []string{"resource type mismatch"} }
	if p.ResourceID != "" && p.ResourceID != "*" && p.ResourceID != r.ResourceID { return false, []string{"resource id mismatch"} }
	if p.SubjectRole != "" && !slices.Contains(r.Roles, p.SubjectRole) { return false, []string{"required role missing"} }
	for k, v := range p.SubjectAttributes { if r.SubjectAttributes[k] != v { return false, []string{fmt.Sprintf("subject attribute %s mismatch", k)} } }
	if p.Relation != "" {
		found := false
		for _, rel := range t.Relations { if rel.SubjectID==r.SubjectID && rel.Relation==p.Relation && rel.ResourceType==r.ResourceType && rel.ResourceID==r.ResourceID { found=true; break } }
		if !found { return false, []string{"required relationship missing"} }
	}
	if p.MaxRisk > 0 && r.Risk > p.MaxRisk { return false, []string{fmt.Sprintf("risk %d exceeds %d", r.Risk, p.MaxRisk)} }
	if p.RequireTrustedDevice && !r.TrustedDevice { return false, []string{"trusted device required"} }
	return true, []string{"all constraints matched"}
}
