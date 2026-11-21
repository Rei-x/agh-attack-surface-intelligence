package scanner

import (
	"fmt"
	"net/netip"
	"strings"
	"unicode"
)

// ValidateTargetEntry checks the syntax of one target or exclusion entry without DNS lookups
// and returns its kind ("ip", "cidr", "range", "ipv6", "domain"). A CIDR/range wider than
// maxIPs (when > 0) is rejected so a typo like /8 fails at input time, not mid-scan.
func ValidateTargetEntry(raw string, maxIPs int) (string, error) {
	entry := cleanTargetString(raw)
	switch {
	case entry == "":
		return "", fmt.Errorf("pusty wpis / empty entry")
	case len(entry) > 253:
		return "", fmt.Errorf("wpis za długi (max 253 znaki) / entry too long (max 253 chars)")
	}
	if r4, ok := parseIPv4Entry(entry); ok {
		n := uint64(r4.end) - uint64(r4.start) + 1
		if maxIPs > 0 && n > uint64(maxIPs) {
			return "", fmt.Errorf("%q obejmuje %d adresów, limit to %d / expands to %d IPs, cap is %d", entry, n, maxIPs, n, maxIPs)
		}
		switch {
		case strings.Contains(entry, "/"):
			return "cidr", nil
		case strings.Contains(entry, "-"):
			return "range", nil
		default:
			return "ip", nil
		}
	}
	if addr, err := netip.ParseAddr(entry); err == nil && addr.Unmap().Is6() {
		return "ipv6", nil
	}
	if pfx, err := netip.ParsePrefix(entry); err == nil && pfx.Addr().Is6() {
		if 128-pfx.Bits() > 16 {
			return "", fmt.Errorf("%q: prefiks IPv6 może obejmować najwyżej /112 (65 536 adresów) / IPv6 prefix wider than /112", entry)
		}
		return "ipv6", nil
	}
	if strings.Contains(entry, "/") || (strings.Contains(entry, "-") && looksNumericRange(entry)) {
		return "", fmt.Errorf("%q nie jest poprawnym adresem, zakresem ani CIDR / not a valid IP, range or CIDR", entry)
	}
	if isLikelyDomain(entry) && validHostname(entry) {
		return "domain", nil
	}
	return "", fmt.Errorf("%q nie jest poprawnym IP, CIDR, zakresem (a-b) ani domeną / not a valid IP, CIDR, range or domain", entry)
}

func looksNumericRange(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c == '.' || c == '-' || c == ' ' || c == ':') {
			return false
		}
	}
	return true
}

// validHostname accepts LDH labels (plus '_' and Unicode letters/digits for IDN names).
func validHostname(s string) bool {
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 {
		return false
	}
	labels := strings.Split(s, ".")
	if tld := labels[len(labels)-1]; strings.Trim(tld, "0123456789") == "" {
		return false // numeric TLD: a mistyped IP such as 300.1.1.1, not a domain
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			switch {
			case c == '-' || c == '_', c >= '0' && c <= '9', c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
			case c > 127 && (unicode.IsLetter(c) || unicode.IsDigit(c)):
			default:
				return false
			}
		}
	}
	return true
}
