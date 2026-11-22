package vulndb

import (
	"fmt"
	"strings"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// The distribution fix table: the first package version that fixes a CVE in one release of
// one distribution. The snapshot has no distribution tracker data, so without this table a
// version match on a distribution package is only "backport possible". With it, a banner at
// or above the fixed revision is "fixed by distribution" and one below it is confirmed as
// still affected (and counted again).
//
// Deliberately tiny and limited to very high profile CVEs. Every row was copied from the
// distribution's own tracker (the Source URL) and checked there; do not add a row from
// memory. A release missing from the table is never assumed fixed or unfixed: its matches
// stay "backport possible". Rows only apply when the banner shows the package revision and
// its upstream version equals the one in Fixed.
type distroFix struct {
	CVE      string
	Product  string // vulndb product key
	Distro   string // as ParseDistroPackage names it: Debian, Ubuntu
	Release  string // 12, 22.04
	Fixed    string // first fixed package version as published, with epoch: 1:9.2p1-2+deb12u3
	Advisory string // DSA / DLA / USN id, "" when the release shipped with the fix
	Source   string
}

const (
	debianTracker = "https://security-tracker.debian.org/tracker/"
	ubuntuTracker = "https://ubuntu.com/security/"
)

var distroFixes = []distroFix{
	// regreSSHion: sshd signal handler race, unauthenticated RCE on glibc Linux. Debian 11
	// (8.4p1) and Ubuntu 20.04 (8.2p1) predate the regression and are not affected.
	{"CVE-2024-6387", "openssh", "Debian", "12", "1:9.2p1-2+deb12u3", "DSA-5724-1", debianTracker + "CVE-2024-6387"},
	{"CVE-2024-6387", "openssh", "Ubuntu", "22.04", "1:8.9p1-3ubuntu0.10", "USN-6859-1", ubuntuTracker + "CVE-2024-6387"},
	{"CVE-2024-6387", "openssh", "Ubuntu", "24.04", "1:9.6p1-3ubuntu13.3", "USN-6859-1", ubuntuTracker + "CVE-2024-6387"},
	// Terrapin: SSH prefix truncation (strict key exchange added by the fix).
	{"CVE-2023-48795", "openssh", "Debian", "10", "1:7.9p1-10+deb10u4", "DLA-3694-1", debianTracker + "CVE-2023-48795"},
	{"CVE-2023-48795", "openssh", "Debian", "11", "1:8.4p1-5+deb11u3", "DSA-5586-1", debianTracker + "CVE-2023-48795"},
	{"CVE-2023-48795", "openssh", "Debian", "12", "1:9.2p1-2+deb12u2", "DSA-5586-1", debianTracker + "CVE-2023-48795"},
	{"CVE-2023-48795", "openssh", "Ubuntu", "20.04", "1:8.2p1-4ubuntu0.10", "USN-6560-1", ubuntuTracker + "CVE-2023-48795"},
	{"CVE-2023-48795", "openssh", "Ubuntu", "22.04", "1:8.9p1-3ubuntu0.5", "USN-6560-1", ubuntuTracker + "CVE-2023-48795"},
	{"CVE-2023-48795", "openssh", "Ubuntu", "24.04", "1:9.6p1-3ubuntu1", "", ubuntuTracker + "CVE-2023-48795"},
}

// splitDebianVersion splits "1:9.2p1-2+deb12u3" into upstream "9.2p1" and revision "2+deb12u3".
func splitDebianVersion(v string) (upstream, revision string) {
	if i := strings.IndexByte(v, ':'); i >= 0 {
		v = v[i+1:]
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return v[:i], v[i+1:]
	}
	return v, ""
}

func lookupDistroFix(product, cve string, p *domain.DistroPackage) *distroFix {
	if p == nil || p.Release == "" {
		return nil
	}
	for i := range distroFixes {
		f := &distroFixes[i]
		if f.CVE != cve || f.Product != product || f.Distro != p.Distro || f.Release != p.Release {
			continue
		}
		if up, _ := splitDebianVersion(f.Fixed); !strings.EqualFold(up, p.Upstream) {
			continue
		}
		return f
	}
	return nil
}

// distroApplicability classifies one version match on a distribution package.
func distroApplicability(product, cve string, p *domain.DistroPackage) (state, note string) {
	f := lookupDistroFix(product, cve, p)
	if f == nil || p.Revision == "" {
		head := "Distribution package"
		if p != nil && p.Label != "" {
			head += " (" + p.Label + ")"
		}
		return domain.ApplicabilityBackportPossible, head + ": fixes may be backported, not confirmed. Version match only; check the package changelog or the distribution security tracker for " + cve + "."
	}
	pkg := p.Label + " package revision " + p.Revision
	adv := f.Advisory
	if adv == "" {
		adv = "fixed before the release"
	}
	_, fixedRev := splitDebianVersion(f.Fixed)
	if compareDebianRevision(p.Revision, fixedRev) >= 0 {
		return domain.ApplicabilityFixedByDistro, fmt.Sprintf("Fixed by distribution: %s is at or above %s (%s).", pkg, f.Fixed, adv)
	}
	return domain.ApplicabilityDistroUnfixed, fmt.Sprintf("Applies: %s predates the distribution fix %s (%s).", pkg, f.Fixed, adv)
}

// fixedByDistro reports whether the fix table shows cve fixed in the package (used to drop
// passive hints the snapshot does not cover).
func fixedByDistro(product, cve string, p *domain.DistroPackage) bool {
	st, _ := distroApplicability(product, cve, p)
	return st == domain.ApplicabilityFixedByDistro
}
