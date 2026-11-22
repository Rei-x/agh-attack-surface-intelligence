package vulndb

import (
	"regexp"
	"strings"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// Distribution packages. Debian, Ubuntu, RHEL, SUSE, Alpine and the other distributions
// backport security fixes into the upstream version they shipped: "OpenSSH 9.2p1" on
// Debian 12 is still 9.2p1 after every security update, only the package revision moves
// (2+deb12u3, 2+deb12u4...). An NVD version-range match on such a build says nothing about
// whether the fix is installed. ParseDistroPackage reads the distribution, release and
// package revision a banner names, so the match is labelled ("distribution package (Debian
// 12)"), kept out of the counts and checked against the small fix table in distrofix.go.

var (
	// Revision after the distribution word, as nmap -sV and the SSH banner print it:
	// "9.2p1 Debian 2+deb12u3", "OpenSSH_8.9p1 Ubuntu-3ubuntu0.10", "7.9p1 Raspbian 10+deb10u2".
	reDebWordRevision = regexp.MustCompile(`(?i)\b(?:debian|ubuntu|raspbian)[ -](\d[0-9a-z.+~:]*)`)
	// A package revision appended to the upstream version: "7.4.3-4ubuntu2.19",
	// "10.11.6-MariaDB-0+deb12u1", "8.0.36-0ubuntu0.22.04.1", "7.4p1-21.el7_9", "1.amzn2".
	reSuffixRevision = regexp.MustCompile(`(?i)(?:^|[\s\-_/])(\d[0-9a-z.+~]*?(?:ubuntu|[+~]deb\d|deb\d+u|\.el\d|\.amzn\d|\.fc\d)[0-9a-z.+~_]*)`)

	reDebRelease  = regexp.MustCompile(`(?i)deb(\d{1,2})u\d|~bpo(\d{1,2})\+`)   // +deb12u3, ~deb12u1, ~bpo12+1
	reUbuRelease  = regexp.MustCompile(`(?i)ubuntu\d+\.(\d{2}\.\d{2})(?:\.|$)`) // 0ubuntu0.22.04.1
	reELRelease   = regexp.MustCompile(`(?i)(?:\.|\b)el(\d{1,2})(?:_\d+)?\b`)   // .el7, .el8_6, .el9_4, "el7"
	reAmznRelease = regexp.MustCompile(`(?i)\bamzn(\d{1,4})\b`)                 // amzn2, amzn2023
	reFCRelease   = regexp.MustCompile(`(?i)\.fc(\d{2})\b`)                     // .fc39

	// Distribution names in banners and Server headers, most specific first.
	distroWords = []struct {
		re   *regexp.Regexp
		name string
	}{
		{regexp.MustCompile(`(?i)\bcentos stream\b`), "CentOS Stream"},
		{regexp.MustCompile(`(?i)\bcentos\b`), "CentOS"},
		{regexp.MustCompile(`(?i)\bred ?hat( enterprise linux)?\b|\brhel\b`), "RHEL"},
		{regexp.MustCompile(`(?i)\brocky linux\b`), "Rocky Linux"},
		{regexp.MustCompile(`(?i)\balma ?linux\b`), "AlmaLinux"},
		{regexp.MustCompile(`(?i)\boracle linux\b`), "Oracle Linux"},
		{regexp.MustCompile(`(?i)\bfedora\b`), "Fedora"},
		{regexp.MustCompile(`(?i)\bamazon linux\b`), "Amazon Linux"},
		{regexp.MustCompile(`(?i)\bopensuse\b`), "openSUSE"},
		{regexp.MustCompile(`(?i)\bsuse\b|\bsles\b`), "SUSE"},
		{regexp.MustCompile(`(?i)\balpine\b`), "Alpine"},
		{regexp.MustCompile(`(?i)\braspbian\b`), "Raspbian"},
		{regexp.MustCompile(`(?i)\bubuntu\b`), "Ubuntu"},
		{regexp.MustCompile(`(?i)\bdebian\b`), "Debian"},
	}

	debianCodenames = map[string]string{"7": "wheezy", "8": "jessie", "9": "stretch", "10": "buster", "11": "bullseye", "12": "bookworm", "13": "trixie", "14": "forky"}
	ubuntuCodenames = map[string]string{
		"14.04": "trusty", "16.04": "xenial", "18.04": "bionic", "20.04": "focal", "22.04": "jammy", "24.04": "noble",
		"23.04": "lunar", "23.10": "mantic", "24.10": "oracular", "25.04": "plucky",
	}

	// upstreamReleases: the upstream version a release ships, for banners whose revision does
	// not name the release ("8.9p1 Ubuntu 3ubuntu0.10" is Ubuntu 22.04). Only OpenSSH, which
	// Debian and Ubuntu never rebase within a release; Apache, PHP and nginx are rebased or
	// shared by several releases and are not inferred.
	upstreamReleases = map[string]map[string]string{
		"openssh/Debian": {"6.7p1": "8", "7.4p1": "9", "7.9p1": "10", "8.4p1": "11", "9.2p1": "12", "10.0p1": "13"},
		"openssh/Ubuntu": {"6.6.1p1": "14.04", "7.2p2": "16.04", "7.6p1": "18.04", "8.2p1": "20.04", "8.9p1": "22.04", "9.6p1": "24.04"},
	}
)

// elFamily lists the distributions whose package releases carry the ".elN" tag.
var elFamily = map[string]bool{"RHEL": true, "CentOS": true, "CentOS Stream": true, "Rocky Linux": true, "AlmaLinux": true, "Oracle Linux": true, "Enterprise Linux": true}

// markerDistro names the distribution a package revision belongs to ("3ubuntu0.10" is Ubuntu).
func markerDistro(rev string) string {
	l := strings.ToLower(rev)
	switch {
	case strings.Contains(l, "ubuntu"):
		return "Ubuntu"
	case reDebRelease.MatchString(l) || strings.Contains(l, "+deb") || strings.Contains(l, "~deb"):
		return "Debian"
	case reELRelease.MatchString(l):
		return "Enterprise Linux"
	case reAmznRelease.MatchString(l):
		return "Amazon Linux"
	case reFCRelease.MatchString(l):
		return "Fedora"
	}
	return ""
}

func wordDistro(s string) string {
	for _, w := range distroWords {
		if w.re.MatchString(s) {
			return w.name
		}
	}
	return ""
}

// packageRevision returns the distribution revision carried by a version string.
func packageRevision(version string) string {
	if m := reDebWordRevision.FindStringSubmatch(version); m != nil {
		return strings.TrimRight(m[1], ".")
	}
	if m := reSuffixRevision.FindStringSubmatch(version); m != nil {
		return strings.TrimRight(m[1], ".")
	}
	return ""
}

func firstGroup(re *regexp.Regexp, texts ...string) string {
	for _, t := range texts {
		if m := re.FindStringSubmatch(t); m != nil {
			for _, g := range m[1:] {
				if g != "" {
					return g
				}
			}
		}
	}
	return ""
}

// ParseDistroPackage reads the distribution package of a version claim. version is the
// version as observed ("9.2p1 Debian 2+deb12u3", "7.4.3-4ubuntu2.19", "1.18.0"); context
// is other text of the same evidence (nmap extrainfo, the whole Server header) and only
// names the distribution and release: the revision is read from version alone, so "PHP/8.1.2-
// 1ubuntu2.14" in a Server header is never taken as Apache's revision. product is the
// vulndb product key ("openssh"), used to infer the release from the upstream version. It
// returns nil when nothing names a distribution.
func ParseDistroPackage(product, version, context string) *domain.DistroPackage {
	rev := packageRevision(version)
	name := wordDistro(version)
	if name == "" {
		name = markerDistro(rev)
	}
	if name == "" {
		name = wordDistro(context)
	}
	if name == "" {
		name = markerDistro(context)
	}
	if name == "" {
		return nil
	}
	p := &domain.DistroPackage{Distro: name, Revision: rev, Upstream: normalizeVersion(version)}
	switch {
	case name == "Debian" || name == "Raspbian":
		p.Release = firstGroup(reDebRelease, rev, version, context)
		p.Codename = debianCodenames[p.Release]
	case name == "Ubuntu":
		p.Release = firstGroup(reUbuRelease, rev, version, context)
		p.Codename = ubuntuCodenames[p.Release]
	case elFamily[name]:
		p.Release = firstGroup(reELRelease, rev, version, context)
		if p.Release != "" {
			p.Codename = "el" + p.Release
		}
	case name == "Amazon Linux":
		p.Release = firstGroup(reAmznRelease, rev, version, context)
	case name == "Fedora":
		p.Release = firstGroup(reFCRelease, rev, version, context)
	}
	if p.Release == "" && p.Upstream != "" {
		family := name
		if family == "Raspbian" {
			family = "Debian"
		}
		if r := upstreamReleases[product+"/"+family][p.Upstream]; r != "" {
			p.Release, p.ReleaseInferred = r, true
			if family == "Debian" {
				p.Codename = debianCodenames[r]
			} else {
				p.Codename = ubuntuCodenames[r]
			}
		}
	}
	p.Label = strings.TrimSpace(name + " " + p.Release)
	return p
}

// packageEvidence returns the version string and context ParseDistroPackage reads for a
// candidate, by where its version came from (the same evidence distroBuild looks at).
func packageEvidence(svc *domain.Service, c candidate) (version, context string) {
	switch c.via {
	case "technology", "http-page":
		return c.version, "" // page content: only a revision in the version itself counts
	case "http-server-header":
		if svc.HTTP != nil {
			return headerToken(svc.HTTP.ServerHeader, c.version), svc.HTTP.ServerHeader
		}
	case "x-powered-by":
		if svc.HTTP != nil {
			for k, v := range svc.HTTP.Headers {
				if strings.EqualFold(k, "X-Powered-By") {
					return headerToken(v, c.version), v
				}
			}
		}
		return c.version, ""
	}
	ctx := svc.Banner
	if svc.HTTP != nil {
		ctx += " " + svc.HTTP.ServerHeader
	}
	return c.version, ctx
}

// headerToken extends a version read from a "name/version" header token to the whole token:
// "PHP/7.4.3-4ubuntu2.19" gives "7.4.3-4ubuntu2.19" for "7.4.3".
func headerToken(header, version string) string {
	i := strings.Index(header, "/"+version)
	if i < 0 {
		return version
	}
	rest := header[i+1:]
	if j := strings.IndexAny(rest, " \t,;()"); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

// compareDebianRevision orders two Debian/Ubuntu package revisions (or full versions) the
// way dpkg does: non-digit runs compare with "~" before everything and letters before other
// characters, digit runs compare numerically ("2+deb12u10" > "2+deb12u3", "3ubuntu0.10" >
// "3ubuntu0.9", "1~deb12u1" < "1").
func compareDebianRevision(a, b string) int {
	order := func(s string, i int) int {
		if i >= len(s) {
			return 0
		}
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			return 0
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
			return int(c)
		case c == '~':
			return -1
		}
		return int(c) + 256
	}
	isDigit := func(s string, i int) bool { return i < len(s) && s[i] >= '0' && s[i] <= '9' }
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		firstDiff := 0
		for (i < len(a) && !isDigit(a, i)) || (j < len(b) && !isDigit(b, j)) {
			ac, bc := order(a, i), order(b, j)
			if ac != bc {
				return sign(ac - bc)
			}
			i++
			j++
		}
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		for isDigit(a, i) && isDigit(b, j) {
			if firstDiff == 0 {
				firstDiff = int(a[i]) - int(b[j])
			}
			i++
			j++
		}
		if isDigit(a, i) {
			return 1
		}
		if isDigit(b, j) {
			return -1
		}
		if firstDiff != 0 {
			return sign(firstDiff)
		}
	}
	return 0
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}
