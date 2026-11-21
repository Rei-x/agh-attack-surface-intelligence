package db

import "sync/atomic"

// PolicyMatcher answers the zone policy query terms (violation:true, policy:<name>) from
// the policy engine's ledger. internal/policy implements it; db cannot import that package
// (it depends on db), so the engine registers itself here.
type PolicyMatcher interface {
	// HostHasViolation: values empty means any open violation on the host.
	HostHasViolation(hostID string, values []string) bool
	ServiceHasViolation(serviceID string, values []string) bool
}

type policyMatcherBox struct{ m PolicyMatcher }

var policyMatcher atomic.Value // policyMatcherBox

// SetPolicyMatcher registers the matcher used by violation: and policy: terms (nil clears).
func SetPolicyMatcher(m PolicyMatcher) { policyMatcher.Store(policyMatcherBox{m: m}) }

func currentPolicyMatcher() PolicyMatcher {
	if b, ok := policyMatcher.Load().(policyMatcherBox); ok {
		return b.m
	}
	return nil
}

// matchPolicyTerm evaluates violation: / policy: for a host (serviceID empty) or a service.
func (t *QueryTerm) matchPolicyTerm(hostID, serviceID string) bool {
	m := currentPolicyMatcher()
	var values []string
	want := true
	if t.Key == "violation" {
		want = t.Values[0] == "true"
	} else {
		values = t.Values
	}
	if m == nil {
		return !want
	}
	var has bool
	if serviceID != "" {
		has = m.ServiceHasViolation(serviceID, values)
	} else {
		has = m.HostHasViolation(hostID, values)
	}
	return has == want
}
