package intelligence

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/signatures"
)

// exposureRisk is the standalone weight of a network exposure by protocol (see
// domain.CombineFactors: the score this exposure alone would justify). Unauthenticated
// control (Docker API, VNC or Redis without auth) and cleartext remote administration
// (telnet, r-services) rank highest: credentials or full control cross the network and these
// are the first things an attacker tries. Databases and other management ports follow; SSH
// is near zero on its own.
type exposureRisk struct {
	reason string
	points int
}

var exposureByService = map[string]exposureRisk{
	"telnet":        {"Telnet: cleartext remote administration (credentials sent unencrypted)", 50},
	"exec":          {"rexec: cleartext remote command execution", 50},
	"login":         {"rlogin: cleartext remote login (host-based trust)", 50},
	"shell":         {"rsh: cleartext remote shell (host-based trust)", 50},
	"ftp":           {"FTP: cleartext login and file transfer", 30},
	"vnc":           {"VNC remote desktop exposed", 30},
	"snmp":          {"SNMP management protocol exposed (cleartext community string)", 20},
	"docker":        {"Docker API exposed (unauthenticated by default = root on the host)", 70},
	"redis":         {"Redis exposed (no authentication by default)", 35},
	"memcache":      {"Memcached exposed (no authentication)", 30},
	"elasticsearch": {"Elasticsearch API exposed (no authentication by default)", 35},
	"mongodb":       {"MongoDB exposed (no authentication by default)", 35},
	"smb":           {"SMB file sharing exposed", 30},
	"rdp":           {"RDP remote desktop exposed", 25},
	"mssql":         {"MSSQL database port exposed", 25},
	"mysql":         {"MySQL database port exposed", 25},
	"postgresql":    {"PostgreSQL database port exposed", 25},
	"oracle":        {"Oracle database listener exposed", 25},
	"ssh":           {"SSH remote access exposed", 3},
	"amqp":          {"AMQP message broker port exposed", 12},
}

var exposurePorts = map[int]string{
	21: "ftp", 23: "telnet", 512: "exec", 513: "login", 514: "shell", 161: "snmp",
	2375: "docker", 6379: "redis", 11211: "memcache", 9200: "elasticsearch", 27017: "mongodb",
	139: "smb", 445: "smb", 3389: "rdp", 1433: "mssql", 3306: "mysql", 5432: "postgresql",
	1521: "oracle", 5672: "amqp", 22: "ssh", 5900: "vnc", 5901: "vnc", 5902: "vnc",
}

var exposureServiceNames = map[string]string{
	"telnet": "telnet", "ftp": "ftp", "exec": "exec", "login": "login", "shell": "shell",
	"vnc": "vnc", "rfb": "vnc", "snmp": "snmp", "redis": "redis", "memcache": "memcache",
	"memcached": "memcache", "mongodb": "mongodb", "mongod": "mongodb", "microsoft-ds": "smb",
	"netbios-ssn": "smb", "ms-wbt-server": "rdp", "ms-sql-s": "mssql", "mysql": "mysql",
	"postgresql": "postgresql", "oracle-tns": "oracle", "ssh": "ssh", "docker": "docker",
	"amqp": "amqp",
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
			r = exposureRisk{"VNC without authentication (anyone can take over the desktop)", 65}
		}
	case "ftp":
		if strings.Contains(banner, "anonymous") {
			r = exposureRisk{"FTP with anonymous login (cleartext)", 45}
		}
	case "redis":
		if strings.Contains(banner, "redis: no authentication") {
			r = exposureRisk{"Redis without authentication (anyone can read and write its data)", 55}
		} else if strings.Contains(banner, "redis: authentication required") {
			r = exposureRisk{"Redis exposed (password protected)", 12}
		}
	case "snmp":
		if strings.Contains(banner, "public") {
			r = exposureRisk{"SNMP answers the default 'public' community", 45}
		}
	}
	return r, true
}

// Standalone weights of the service-level flags (domain.CombineFactors).
const (
	WeightAdminPanel   = 35
	WeightStaging      = 20
	WeightBMC          = 50
	WeightIoT          = 18
	WeightDebugHeaders = 15
	WeightSignatureMax = 25 // strongest matched signature that no flag above already covers
)

// ScoreService calculates a transparent 0-100 Interestingness Score for a service with an
// explainable list of factors whose Points add up to the score. Strong signals (exposed
// management, unauthenticated or cleartext control, BMC) weigh the most; hygiene findings
// (headers, cookies, certificates) are capped together (domain.HygieneCap). CVE, EOL and
// verified factors are added later by eol.ApplyScore with the same combination.
func ScoreService(svc *domain.Service, sigMatches []signatures.MatchResult) (int, []domain.InterestingnessFactor) {
	if svc == nil {
		return 0, nil
	}

	var factors []domain.InterestingnessFactor
	add := func(reason string, weight int) {
		if weight > 0 {
			factors = append(factors, domain.InterestingnessFactor{Reason: reason, Weight: weight})
		}
	}
	hygiene := func(reason string, weight int) {
		if weight > 0 {
			factors = append(factors, domain.InterestingnessFactor{Reason: reason, Weight: weight, Kind: domain.FactorKindHygiene})
		}
	}

	if svc.IsAdminPanel {
		add("Admin panel or management surface exposed", WeightAdminPanel)
	}
	if svc.IsStagingEnv {
		add("Staging, dev, test, or debug environment detected", WeightStaging)
	}
	isBMC := false
	for _, t := range svc.Technologies {
		if t.Category == "bmc" {
			isBMC = true
			break
		}
	}
	if isBMC {
		add("Out-of-band server management (BMC: iDRAC/iLO/IPMI) exposed - full control of the server", WeightBMC)
	} else if svc.IsIoT {
		add("IoT, printer, camera or network device management interface", WeightIoT)
	}

	if r, ok := classifyExposure(svc); ok {
		add(r.reason, r.points)
	}

	// HTTP / TLS hygiene (low signal, capped together) and debug exposure.
	if fp := svc.HTTP; fp != nil {
		if fp.TLS != nil {
			if fp.TLS.IsExpired {
				hygiene("TLS certificate is expired", 8)
			} else if fp.TLS.DaysToExpiry >= 0 && fp.TLS.DaysToExpiry <= 30 {
				hygiene(fmt.Sprintf("TLS certificate expiring soon (%d days)", fp.TLS.DaysToExpiry), 4)
			}
			if fp.TLS.IsSelfSigned {
				hygiene("Self-signed TLS certificate", 4)
			}
		}

		if len(fp.MissingSecHeaders) >= 3 {
			hygiene(fmt.Sprintf("Missing %d key HTTP security headers", len(fp.MissingSecHeaders)), 5)
		} else if len(fp.MissingSecHeaders) > 0 {
			hygiene(fmt.Sprintf("Missing %d HTTP security header(s)", len(fp.MissingSecHeaders)), 2)
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
			hygiene(fmt.Sprintf("%d cookie(s) missing HttpOnly/Secure flags", insecureCookies), 4)
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
			add("Debug HTTP headers exposed in response", WeightDebugHeaders)
		}
		if hasAuthHeader {
			hygiene("HTTP Basic/Digest authentication challenge exposed", 3)
		}
	}

	if name, more, pts := strongestSignature(svc, isBMC, sigMatches); pts > 0 {
		reason := "Detection signature: " + name
		if more > 0 {
			reason += fmt.Sprintf(" (+%d more)", more)
		}
		add(reason, pts)
	}

	return domain.CombineFactors(factors)
}

// strongestSignature picks the matched signature with the most points that is not already
// represented by a flag factor (admin panel, staging, BMC/IoT) or by the hygiene factors
// (certificate, cookie and header signatures), so one finding is not counted twice.
func strongestSignature(svc *domain.Service, isBMC bool, matches []signatures.MatchResult) (string, int, int) {
	best, bestPts, n := "", 0, 0
	for _, m := range matches {
		if !m.Matched || m.Signature.InterestingPts <= 0 {
			continue
		}
		switch m.Signature.Category {
		case "interesting_header", "interesting_cookie":
			continue
		case "admin_panel":
			if svc.IsAdminPanel {
				continue
			}
		case "staging":
			if svc.IsStagingEnv {
				continue
			}
		case "bmc", "iot":
			if isBMC || svc.IsIoT {
				continue
			}
		}
		n++
		if m.Signature.InterestingPts > bestPts {
			best, bestPts = m.Signature.Name, m.Signature.InterestingPts
		}
	}
	if bestPts > WeightSignatureMax {
		bestPts = WeightSignatureMax
	}
	return best, n - 1, bestPts
}

// Host-level weights (domain.CombineFactors).
const (
	WeightOtherServicesMax = 20 // further high-risk services together
	WeightNewHost          = 5  // every host is new on a first scan, so this is context only
	WeightReactivated      = 10
	WeightIntermittent     = 5
	WeightNonProd          = 8
	WeightLargeSurface     = 5
	WeightTimeAnomaly      = 15
)

// ScoreHost computes a host-level 0-100 Interestingness Score: its riskiest service (whose
// score enters as the first factor, so it is never diluted), further high-risk services at
// a third of their score with diminishing returns (capped together), then lifecycle,
// environment and anomaly context.
// The factor Points add up to the score.
func ScoreHost(host *domain.Host, services []domain.Service, changes []domain.ChangeEvent) (int, []domain.InterestingnessFactor) {
	if host == nil {
		return 0, nil
	}

	var factors []domain.InterestingnessFactor
	add := func(reason string, weight int) {
		if weight > 0 {
			factors = append(factors, domain.InterestingnessFactor{Reason: reason, Weight: weight})
		}
	}
	open := func(s domain.Service) bool { return s.State == "" || s.State == "open" }

	maxIdx := -1
	for i := range services {
		if !open(services[i]) {
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
			why = ": " + topReasons(top.InterestingFactors)
		}
		add(fmt.Sprintf("Highest-risk service %d/%s %s%s", top.Port, nonEmptyStr(top.Protocol, "tcp"), nonEmptyStr(top.ServiceName, "unknown"), why), top.Interestingness)
	}
	// Further high-risk services add up with diminishing returns (two cleartext admin
	// protocols are worse than one, ten database ports are not ten times worse).
	var ports []string
	rest := 1.0
	for i := range services {
		if i != maxIdx && services[i].Interestingness >= 25 && open(services[i]) {
			ports = append(ports, strconv.Itoa(services[i].Port))
			rest *= 1 - float64(services[i].Interestingness)/300
		}
	}
	if len(ports) > 0 {
		w := int(math.Round(100 * (1 - rest)))
		if w > WeightOtherServicesMax {
			w = WeightOtherServicesMax
		}
		add(fmt.Sprintf("%d more high-risk service(s) on the same host (port %s)", len(ports), strings.Join(ports, ", ")), w)
	}

	switch host.LifecycleState {
	case domain.HostStateNew:
		add("Newly discovered host on network", WeightNewHost)
	case domain.HostStateReactivated:
		add("Previously inactive host reactivated", WeightReactivated)
	case domain.HostStateIntermittent:
		add("Intermittent / unstable host availability", WeightIntermittent)
	}

	env := strings.ToLower(strings.TrimSpace(host.Environment))
	if env == "staging" || env == "dev" || env == "test" {
		add(fmt.Sprintf("Non-production environment (%s)", env), WeightNonProd)
	}

	if len(services) >= 5 {
		add(fmt.Sprintf("Large attack surface (%d open services)", len(services)), WeightLargeSurface)
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
		add("Time-of-day availability anomaly detected", WeightTimeAnomaly)
	}

	return domain.CombineFactors(factors)
}

// topReasons names the strongest one or two factors of a service for the host explanation.
func topReasons(fs []domain.InterestingnessFactor) string {
	sorted := append([]domain.InterestingnessFactor(nil), fs...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Points > sorted[j].Points })
	out := sorted[0].Reason
	if len(sorted) > 1 && sorted[1].Points >= 10 {
		out += "; " + sorted[1].Reason
	}
	return out
}

func nonEmptyStr(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}
