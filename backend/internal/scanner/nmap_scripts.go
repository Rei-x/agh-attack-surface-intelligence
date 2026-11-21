package scanner

import (
	"strings"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// Edge cases of real-world nmap XML, found by running ParseNmapXML against the
// OWASP secureCodeBox nmap parser fixtures (testdata/scb, Apache-2.0):
//   - <address addrtype="mac"> next to the IP must never become the host IP;
//   - the same IP can appear in several <host> blocks (merged into one host);
//   - NSE <script> output from imports (we never run scripts ourselves) carries
//     a banner or a well-known weak configuration worth keeping as a tag.

// nmapScriptXML is an NSE result (<script id=".." output=".."/>). Only id and output
// are kept; structured <table>/<elem> children are not needed for the checks below.
type nmapScriptXML struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

// nmapHostScriptXML is <hostscript>; a pointer so generated XML omits it when empty.
type nmapHostScriptXML struct {
	Scripts []nmapScriptXML `xml:"script"`
}

// nmapHostIP picks the host's IP address (IPv4 preferred, then IPv6), ignoring MAC addresses.
func nmapHostIP(addrs []nmapAddrXML) string {
	var v6 string
	for _, a := range addrs {
		switch a.AddrType {
		case "ipv4":
			return a.Addr
		case "ipv6":
			if v6 == "" {
				v6 = a.Addr
			}
		}
	}
	return v6
}

// nseEscapes undoes the \xNN escaping nmap applies to non-printable banner bytes.
var nseEscapes = strings.NewReplacer(`\x0D\x0A`, "\n", `\x0D`, "\n", `\x0A`, "\n", `\x09`, "\t")

// applyNmapScripts uses port-level NSE output from imported XML: the `banner` script fills
// an empty banner, and known weak configurations become tags (same checks as the
// secureCodeBox nmap parser: ftp-anon and smb-protocols).
func applyNmapScripts(svc *domain.ObservedService, scripts []nmapScriptXML) {
	for _, sc := range scripts {
		out := strings.TrimSpace(sc.Output)
		switch sc.ID {
		case "banner":
			if svc.Banner == "" && out != "" {
				svc.Banner = truncateStr(strings.TrimSpace(sanitizePrintable(nseEscapes.Replace(out))), 512)
			}
		case "ftp-anon":
			if strings.Contains(strings.ToLower(out), "anonymous ftp login allowed") {
				svc.Tags = appendUnique(svc.Tags, "ftp-anonymous")
			}
		case "smb-protocols":
			if strings.Contains(out, "SMBv1") {
				svc.Tags = appendUnique(svc.Tags, "smbv1")
			}
		}
	}
}

// applyNmapHostScripts attaches host-level script results (<hostscript>) to the service
// they describe; smb-protocols belongs to the SMB port (445, else 139).
func applyNmapHostScripts(svcs []domain.ObservedService, scripts []nmapScriptXML) {
	for _, sc := range scripts {
		if sc.ID != "smb-protocols" {
			continue
		}
		target := -1
		for i := range svcs {
			if svcs[i].Port == 445 || (svcs[i].Port == 139 && target < 0) {
				target = i
			}
		}
		if target >= 0 {
			applyNmapScripts(&svcs[target], []nmapScriptXML{sc})
		}
	}
}

// mergeDuplicateHosts folds repeated <host> blocks for the same IP into the first one:
// alive if any block was up, services unioned by port/protocol, names kept.
func mergeDuplicateHosts(hosts []domain.ObservedHost) []domain.ObservedHost {
	idx := make(map[string]int, len(hosts))
	out := hosts[:0]
	for _, h := range hosts {
		i, dup := idx[h.IP]
		if !dup {
			idx[h.IP] = len(out)
			out = append(out, h)
			continue
		}
		m := &out[i]
		m.IsAlive = m.IsAlive || h.IsAlive
		if m.Hostname == "" {
			m.Hostname = h.Hostname
		}
		if m.OSGuess == "" {
			m.OSGuess = h.OSGuess
		}
		for _, d := range h.Domains {
			m.Domains = appendUnique(m.Domains, d)
		}
		for _, s := range h.Services {
			found := false
			for j := range m.Services {
				if m.Services[j].Port == s.Port && strings.EqualFold(m.Services[j].Protocol, s.Protocol) {
					found = true
					if m.Services[j].Product == "" && s.Product != "" {
						m.Services[j] = s
					}
					break
				}
			}
			if !found {
				m.Services = append(m.Services, s)
			}
		}
	}
	return out
}
