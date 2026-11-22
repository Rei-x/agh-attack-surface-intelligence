package vulndb

import (
	"regexp"
	"strconv"
	"strings"
)

// Version comparison for NVD ranges.
//
// NVD bounds and observed versions come in many shapes: "2.4.49", "8.9p1" (OpenSSH portable),
// "1.0.2k" (OpenSSL letter releases), "1.3.5e" (ProFTPD), "3.0.0-rc1", "10.6.16-MariaDB-0ubuntu".
// A version is normalised to its leading release token and split into segments: runs of
// digits compare numerically, runs of letters lexically. Pre-release words (alpha, beta, rc,
// pre, dev, m) sort BEFORE the release they precede ("3.0.0-rc1" < "3.0.0"); any other
// letter suffix sorts AFTER it ("8.9" < "8.9p1", "1.0.2" < "1.0.2k"). Missing numeric
// components count as zero ("4.7" == "4.7.0").

var reRelease = regexp.MustCompile(`^\d+(?:\.\d+)*(?:[a-z]+\d*)?(?:[-_.~]?(?:rc|beta|alpha|pre|dev)[-_.]?\d*|[-_.~]?m\d+)?`)

// normalizeVersion returns the leading release token of an observed or NVD version, or ""
// when it does not start with a number. "8.9p1 Ubuntu-3ubuntu0.6" -> "8.9p1",
// "2.4.29 (Ubuntu)" -> "2.4.29", "v1.2.3" -> "1.2.3", "1.0.2k-fips" -> "1.0.2k".
func normalizeVersion(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, " (+"); i > 0 {
		v = v[:i]
	}
	return reRelease.FindString(v)
}

type segment struct {
	num   int
	str   string
	isNum bool
}

var preRelease = map[string]bool{"alpha": true, "beta": true, "rc": true, "pre": true, "dev": true, "m": true}

// segments splits v into numeric and letter runs. Callers pass a small stack buffer: version
// checks run for every service against every candidate CVE range during ingest, and the
// growing slices of a plain append were most of the ingest's allocations.
func segments(v string, out []segment) []segment {
	i := 0
	for i < len(v) {
		c := v[i]
		switch {
		case c >= '0' && c <= '9':
			j := i
			for j < len(v) && v[j] >= '0' && v[j] <= '9' {
				j++
			}
			n, _ := strconv.Atoi(v[i:j])
			out = append(out, segment{num: n, isNum: true})
			i = j
		case c >= 'a' && c <= 'z':
			j := i
			for j < len(v) && v[j] >= 'a' && v[j] <= 'z' {
				j++
			}
			out = append(out, segment{str: v[i:j]})
			i = j
		default:
			i++
		}
	}
	return out
}

// numericParts counts the leading dotted numeric components ("4.7" -> 2, "8.9p1" -> 2).
func numericParts(v string) int {
	n := 0
	var buf [8]segment
	for _, s := range segments(v, buf[:0]) {
		if !s.isNum {
			break
		}
		n++
	}
	return n
}

// CompareVersions compares two versions (see the package comment above): -1, 0 or 1.
func CompareVersions(a, b string) int {
	var abuf, bbuf [8]segment
	as, bs := segments(normalizeVersion(a), abuf[:0]), segments(normalizeVersion(b), bbuf[:0])
	for i := 0; i < len(as) || i < len(bs); i++ {
		var x, y *segment
		if i < len(as) {
			x = &as[i]
		}
		if i < len(bs) {
			y = &bs[i]
		}
		if c := compareSegment(x, y); c != 0 {
			return c
		}
	}
	return 0
}

// compareSegment orders one segment pair; nil means the version ended.
func compareSegment(x, y *segment) int {
	switch {
	case x == nil && y == nil:
		return 0
	case x == nil:
		return -compareSegment(y, nil)
	case y == nil:
		if x.isNum {
			if x.num > 0 {
				return 1
			}
			return 0
		}
		if preRelease[x.str] {
			return -1 // 3.0.0-rc1 < 3.0.0
		}
		return 1 // 8.9p1 > 8.9
	case x.isNum && y.isNum:
		switch {
		case x.num < y.num:
			return -1
		case x.num > y.num:
			return 1
		}
		return 0
	case x.isNum != y.isNum:
		// "1.0.2" vs "1.0.rc": a number beats a pre-release word, loses to a suffix letter.
		if x.isNum {
			if preRelease[y.str] {
				return 1
			}
			return -1
		}
		return -compareSegment(y, x)
	}
	xp, yp := preRelease[x.str], preRelease[y.str]
	switch {
	case xp && !yp:
		return -1
	case !xp && yp:
		return 1
	}
	return strings.Compare(x.str, y.str)
}

// Range is one affected version range of a CVE for a product (NVD cpeMatch semantics).
// Exact is set for a single listed version; otherwise any of the four bounds may be set.
type Range struct {
	Exact string `json:"x,omitempty"`
	SI    string `json:"si,omitempty"` // versionStartIncluding
	SE    string `json:"se,omitempty"` // versionStartExcluding
	EI    string `json:"ei,omitempty"` // versionEndIncluding
	EE    string `json:"ee,omitempty"` // versionEndExcluding
}

// MatchResult is the outcome of testing a version against a range.
type MatchResult int

const (
	NoMatch MatchResult = iota
	// PossibleMatch: the observed version is incomplete ("2.4" against "< 2.4.50"), so it
	// may or may not be in the range.
	PossibleMatch
	Match
)

// matchVersion tests v against r. fullParts is the number of numeric components a complete
// version of the product has (OpenSSH "8.9" is complete with 2, nginx needs 3): an observed
// version with fewer components stands for the whole interval [v, next(v)) and is compared
// as such.
func (r Range) matchVersion(v string, fullParts int) MatchResult {
	nv := normalizeVersion(v)
	if nv == "" {
		return NoMatch
	}
	parts := numericParts(nv)
	partial := parts < fullParts && !hasSuffix(nv)
	if r.Exact != "" {
		if !partial {
			if CompareVersions(nv, r.Exact) == 0 {
				return Match
			}
			return NoMatch
		}
		if hasPrefixVersion(normalizeVersion(r.Exact), nv) {
			return PossibleMatch
		}
		return NoMatch
	}
	if !partial {
		if r.contains(nv) {
			return Match
		}
		return NoMatch
	}
	// Partial: interval [lo, hi).
	lo, hi := nv, bumpLast(nv)
	// Entirely below the start or above the end: no.
	if r.SI != "" && CompareVersions(hi, r.SI) <= 0 {
		return NoMatch
	}
	if r.SE != "" && CompareVersions(hi, r.SE) <= 0 {
		return NoMatch
	}
	if r.EE != "" && CompareVersions(lo, r.EE) >= 0 {
		return NoMatch
	}
	if r.EI != "" && CompareVersions(lo, r.EI) > 0 {
		return NoMatch
	}
	// Entirely inside: [lo, hi) within the range.
	inside := true
	if r.SI != "" && CompareVersions(lo, r.SI) < 0 {
		inside = false
	}
	if r.SE != "" && CompareVersions(lo, r.SE) <= 0 {
		inside = false
	}
	if r.EE != "" && CompareVersions(hi, r.EE) > 0 {
		inside = false
	}
	if r.EI != "" && CompareVersions(hi, r.EI) > 0 {
		inside = false
	}
	if inside {
		return Match
	}
	return PossibleMatch
}

func (r Range) contains(v string) bool {
	if r.SI != "" && CompareVersions(v, r.SI) < 0 {
		return false
	}
	if r.SE != "" && CompareVersions(v, r.SE) <= 0 {
		return false
	}
	if r.EE != "" && CompareVersions(v, r.EE) >= 0 {
		return false
	}
	if r.EI != "" && CompareVersions(v, r.EI) > 0 {
		return false
	}
	return r.SI != "" || r.SE != "" || r.EE != "" || r.EI != ""
}

// String renders the range for evidence ("4.7 <= v < 4.7.19").
func (r Range) String() string {
	if r.Exact != "" {
		return "= " + r.Exact
	}
	var lo, hi string
	switch {
	case r.SI != "":
		lo = r.SI + " <= "
	case r.SE != "":
		lo = r.SE + " < "
	}
	switch {
	case r.EE != "":
		hi = " < " + r.EE
	case r.EI != "":
		hi = " <= " + r.EI
	}
	return strings.TrimSpace(lo + "v" + hi)
}

// hasSuffix: "8.9p1" or "1.0.2k" carry a letter suffix, which makes them specific releases.
func hasSuffix(v string) bool {
	var buf [8]segment
	for _, s := range segments(v, buf[:0]) {
		if !s.isNum {
			return true
		}
	}
	return false
}

// hasPrefixVersion reports whether full starts with the dotted components of prefix
// ("4.7.5" has prefix "4.7", "4.70" does not).
func hasPrefixVersion(full, prefix string) bool {
	return full == prefix || strings.HasPrefix(full, prefix+".")
}

// bumpLast increments the last numeric component ("4.7" -> "4.8", "2" -> "3").
func bumpLast(v string) string {
	parts := strings.Split(v, ".")
	n, err := strconv.Atoi(parts[len(parts)-1])
	if err != nil {
		return v
	}
	parts[len(parts)-1] = strconv.Itoa(n + 1)
	return strings.Join(parts, ".")
}
