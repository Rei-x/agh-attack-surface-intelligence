package intelligence

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/signatures"
)

// exposureRisk is the base score of a network exposure by protocol. Cleartext remote
// administration (telnet, r-services, FTP logins, VNC without auth) is scored as high as an
// exposed admin panel: credentials cross the network unencrypted and these are the first
// things an attacker tries. Databases and unauthenticated-by-default APIs follow.
type exposureRisk struct {
	reason string
	points int
}

var exposureByService = map[string]exposureRisk{
	"telnet":        {"Telnet: cleartext remote administration (credentials sent unencrypted)", 45},
	"exec":          {"rexec: cleartext remote command execution", 45},
	"login":         {"rlogin: cleartext remote login (host-based trust)", 45},
	"shell":         {"rsh: cleartext remote shell (host-based trust)", 45},
	"ftp":           {"FTP: cleartext login and file transfer", 35},
	"vnc":           {"VNC remote desktop exposed", 30},
	"snmp":          {"SNMP management protocol exposed (cleartext community string)", 25},
	"docker":        {"Docker API exposed (unauthenticated by default = root on the host)", 45},
	"redis":         {"Redis exposed (no authentication by default)", 30},
	"memcache":      {"Memcached exposed (no authentication)", 30},
	"elasticsearch": {"Elasticsearch API exposed (no authentication by default)", 30},
	"mongodb":       {"MongoDB exposed (no authentication by default)", 30},
	"smb":           {"SMB file sharing exposed", 30},
	"rdp":           {"RDP remote desktop exposed", 25},
	"mssql":         {"MSSQL database port exposed", 25},
	"mysql":         {"MySQL database port exposed", 25},
	"postgresql":    {"PostgreSQL database port exposed", 25},
	"oracle":        {"Oracle database listener exposed", 25},
	"ssh":           {"SSH remote access exposed", 5},
}

var exposurePorts = map[int]string{
	21: "ftp", 23: "telnet", 512: "exec", 513: "login", 514: "shell", 161: "snmp",
	2375: "docker", 6379: "redis", 11211: "memcache", 9200: "elasticsearch", 27017: "mongodb",
	139: "smb", 445: "smb", 3389: "rdp", 1433: "mssql", 3306: "mysql", 5432: "postgresql",
	1521: "oracle", 22: "ssh", 5900: "vnc", 5901: "vnc", 5902: "vnc",
}

var exposureServiceNames = map[string]string{
	"telnet": "telnet", "ftp": "ftp", "exec": "exec", "login": "login", "shell": "shell",
	"vnc": "vnc", "rfb": "vnc", "snmp": "snmp", "redis": "redis", "memcache": "memcache",
	"memcached": "memcache", "mongodb": "mongodb", "mongod": "mongodb", "microsoft-ds": "smb",
	"netbios-ssn": "smb", "ms-wbt-server": "rdp", "ms-sql-s": "mssql", "mysql": "mysql",
	"postgresql": "postgresql", "oracle-tns": "oracle", "ssh": "ssh", "docker": "docker",
}

// classifyExposure returns the exposure risk of a service (service name wins over port so
// telnet on 2323 is still telnet and HTTP on port 23 is not).
func classifyExposure(svc *domain.Service) (exposureRisk, bool) {
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(svc.ServiceName)), "?")
	key, ok := exposureServiceNames[name]
	if !ok && (name == "" || name == "tcp" || name == "udp" || name == "unknown") {
		key, ok = exposurePorts[svc.Port]
	}
	if !ok {
		return exposureRisk{}, false
	}
	r := exposureByService[key]
	banner := strings.ToLower(svc.Banner)
	switch key {
	case "vnc":
		if strings.Contains(banner, "no authentication") || strings.Contains(banner, "security types: none") || strings.Contains(banner, "auth: none") {
			r = exposureRisk{"VNC without authentication (anyone can take over the desktop)", 50}
		}
	case "ftp":
		if strings.Contains(banner, "anonymous") {
			r = exposureRisk{"FTP with anonymous login (cleartext)", 40}
		}
	case "snmp":
		if strings.Contains(banner, "public") {
			r = exposureRisk{"SNMP answers the default 'public' community", 40}
		}
	}
	return r, true
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
	isBMC := false
	for _, t := range svc.Technologies {
		if t.Category == "bmc" {
			isBMC = true
			break
		}
	}
	if isBMC {
		add("Out-of-band server management (BMC: iDRAC/iLO/IPMI) exposed - full control of the server", 30)
	} else if svc.IsIoT {
		add("IoT, printer, camera or network device management interface", 18)
	}

	if r, ok := classifyExposure(svc); ok {
		add(r.reason, r.points)
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

	maxIdx := -1
	for i := range services {
		if services[i].State != "" && services[i].State != "open" {
			continue
		}
		if maxIdx < 0 || services[i].Interestingness > services[maxIdx].Interestingness {
			maxIdx = i
		}
	}
	if maxIdx >= 0 && services[maxIdx].Interestingness > 0 {
		top := services[maxIdx]
		why := ""
		if len(top.InterestingFactors) > 0 {
			why = ": " + top.InterestingFactors[0].Reason
		}
		add(fmt.Sprintf("Highest-risk service %d/%s %s%s", top.Port, nonEmptyStr(top.Protocol, "tcp"), nonEmptyStr(top.ServiceName, "unknown"), why), top.Interestingness)
	}
	// Further high-risk services add up (two cleartext admin protocols are worse than one).
	others := 0
	for i := range services {
		if i != maxIdx && services[i].Interestingness >= 25 && (services[i].State == "" || services[i].State == "open") {
			others++
		}
	}
	if others > 0 {
		pts := others * 5
		if pts > 15 {
			pts = 15
		}
		add(fmt.Sprintf("%d more high-risk service(s) on the same host", others), pts)
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

func nonEmptyStr(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}
