package intelligence

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/signatures"
)

var highRiskPorts = map[int]string{
	21:    "FTP exposed",
	23:    "Telnet unencrypted management port exposed",
	445:   "SMB port 445 exposed",
	1433:  "MSSQL database port exposed",
	2375:  "Unencrypted Docker API port 2375 exposed",
	3306:  "MySQL database port exposed",
	3389:  "RDP remote desktop exposed",
	5432:  "PostgreSQL database port exposed",
	5900:  "VNC remote desktop exposed",
	6379:  "Redis database port exposed",
	9200:  "Elasticsearch API port exposed",
	27017: "MongoDB database port exposed",
}

// ScoreService calculates a transparent 0-100 Interestingness Score for a service
// with an explainable list of InterestingnessFactor entries.
func ScoreService(svc *domain.Service, sigMatches []signatures.MatchResult) (int, []domain.InterestingnessFactor) {
	if svc == nil {
		return 0, nil
	}

	var factors []domain.InterestingnessFactor
	add := func(reason string, pts int) {
		if pts <= 0 {
			return
		}
		factors = append(factors, domain.InterestingnessFactor{
			Reason: reason,
			Points: pts,
		})
	}

	if svc.IsAdminPanel {
		add("Admin panel or management surface exposed", 25)
	}
	if svc.IsStagingEnv {
		add("Staging, dev, test, or debug environment detected", 20)
	}
	if svc.IsIoT {
		add("IoT, printer, camera, or BMC management device detected", 18)
	}

	if desc, ok := highRiskPorts[svc.Port]; ok {
		add(desc, 14)
	} else if svc.Port == 22 {
		add("SSH remote access port exposed", 5)
	}

	// HTTP / TLS specific risk & hygiene signals.
	if fp := svc.HTTP; fp != nil {
		if fp.TLS != nil {
			if fp.TLS.IsExpired {
				add("TLS certificate is expired", 20)
			} else if fp.TLS.DaysToExpiry >= 0 && fp.TLS.DaysToExpiry <= 30 {
				add(fmt.Sprintf("TLS certificate expiring soon (%d days)", fp.TLS.DaysToExpiry), 12)
			}
			if fp.TLS.IsSelfSigned {
				add("Self-signed TLS certificate", 10)
			}
		}

		if len(fp.MissingSecHeaders) >= 3 {
			add(fmt.Sprintf("Missing %d key HTTP security headers", len(fp.MissingSecHeaders)), 8)
		} else if len(fp.MissingSecHeaders) > 0 {
			add(fmt.Sprintf("Missing %d HTTP security header(s)", len(fp.MissingSecHeaders)), 4)
		}

		insecureCookies := 0
		for _, c := range fp.Cookies {
			for _, fl := range c.Flags {
				if fl == "missing_httponly" || fl == "missing_secure" {
					insecureCookies++
					break
				}
			}
		}
		if insecureCookies > 0 {
			add(fmt.Sprintf("%d cookie(s) missing HttpOnly/Secure flags", insecureCookies), 8)
		}

		hasDebugHeader := false
		hasAuthHeader := false
		for _, ih := range fp.InterestingHeaders {
			ihl := strings.ToLower(ih)
			if strings.HasPrefix(ihl, "x-debug") {
				hasDebugHeader = true
			}
			if strings.HasPrefix(ihl, "www-authenticate") {
				hasAuthHeader = true
			}
		}
		if hasDebugHeader {
			add("Debug HTTP headers exposed in response", 12)
		}
		if hasAuthHeader {
			add("HTTP Basic/Digest authentication challenge exposed", 8)
		}
	}

	// Add bounded signature points (preventing duplicate double-counting with base flags).
	sigPts := 0
	for _, m := range sigMatches {
		if m.Matched && m.Signature.InterestingPts > 0 {
			sigPts += m.Signature.InterestingPts
		}
	}
	if sigPts > 25 {
		sigPts = 25
	}
	if sigPts > 0 {
		add(fmt.Sprintf("Matched %d detection signature(s)", len(sigMatches)), sigPts)
	}

	total := 0
	for _, f := range factors {
		total += f.Points
	}
	if total > 100 {
		total = 100
	}

	sort.Slice(factors, func(i, j int) bool {
		if factors[i].Points != factors[j].Points {
			return factors[i].Points > factors[j].Points
		}
		return factors[i].Reason < factors[j].Reason
	})

	return total, factors
}

// ScoreHost computes a host-level 0-100 Interestingness Score aggregating its
// highest-risk service, lifecycle state, environment, and recent anomalies.
func ScoreHost(host *domain.Host, services []domain.Service, changes []domain.ChangeEvent) (int, []domain.InterestingnessFactor) {
	if host == nil {
		return 0, nil
	}

	var factors []domain.InterestingnessFactor
	add := func(reason string, pts int) {
		if pts <= 0 {
			return
		}
		factors = append(factors, domain.InterestingnessFactor{
			Reason: reason,
			Points: pts,
		})
	}

	maxSvcScore := 0
	var maxSvcPort int
	for _, s := range services {
		if s.Interestingness > maxSvcScore {
			maxSvcScore = s.Interestingness
			maxSvcPort = s.Port
		}
	}
	if maxSvcScore > 0 {
		add(fmt.Sprintf("Highest-risk exposed service (port %d)", maxSvcPort), maxSvcScore)
	}

	switch host.LifecycleState {
	case domain.HostStateNew:
		add("Newly discovered host on network", 12)
	case domain.HostStateReactivated:
		add("Previously inactive host reactivated", 14)
	case domain.HostStateIntermittent:
		add("Intermittent / unstable host availability", 8)
	}

	env := strings.ToLower(strings.TrimSpace(host.Environment))
	if env == "staging" || env == "dev" || env == "test" {
		add(fmt.Sprintf("Non-production environment (%s)", env), 10)
	}

	if len(services) >= 5 {
		add(fmt.Sprintf("Large attack surface (%d open services)", len(services)), 8)
	}

	anomalyCount := 0
	for _, ch := range changes {
		if ch.HostID == host.ID || (ch.HostIP != "" && ch.HostIP == host.IP) {
			if ch.IsTimeAnomaly {
				anomalyCount++
			}
		}
	}
	if anomalyCount > 0 {
		add("Time-of-day availability anomaly detected", 15)
	}

	total := 0
	for _, f := range factors {
		total += f.Points
	}
	if total > 100 {
		total = 100
	}

	sort.Slice(factors, func(i, j int) bool {
		if factors[i].Points != factors[j].Points {
			return factors[i].Points > factors[j].Points
		}
		return factors[i].Reason < factors[j].Reason
	})

	return total, factors
}
