package vulndb

import (
	"testing"
	"time"
)

var testNow = time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)

func TestNormalizeVersion(t *testing.T) {
	cases := map[string]string{
		"8.9p1 Ubuntu-3ubuntu0.6": "8.9p1",
		"2.4.29 (Ubuntu)":         "2.4.29",
		"v1.2.3":                  "1.2.3",
		"1.0.2k-fips":             "1.0.2k",
		"10.6.16-MariaDB-0ubuntu": "10.6.16",
		"3.0.0-rc1":               "3.0.0-rc1",
		"1.3.5e":                  "1.3.5e",
		"4.7":                     "4.7",
		"unknown":                 "",
		"":                        "",
	}
	for in, want := range cases {
		if got := normalizeVersion(in); got != want {
			t.Errorf("normalizeVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.18.0", "1.18.0", 0},
		{"4.7", "4.7.0", 0},
		{"4.7", "4.7.1", -1},
		{"4.7.19", "4.7.2", 1},
		{"2.4.49", "2.4.50", -1},
		{"10.0", "9.9.9", 1},
		{"8.9p1", "9.8p1", -1},
		{"8.5", "8.5p1", -1},
		{"9.8p1", "9.8", 1},
		{"1.0.2k", "1.0.2", 1},
		{"1.0.2k", "1.0.2l", -1},
		{"3.0.0-rc1", "3.0.0", -1},
		{"3.0.0-beta2", "3.0.0-rc1", -1},
		{"3.0.0-rc2", "3.0.0-rc10", -1},
		{"3.0.0", "3.0.1-rc1", -1},
		{"1.3.5e", "1.3.5b", 1},
		{"1.3.5", "1.3.6rc1", -1},
		{"7.4.33 (Debian)", "7.4.33", 0},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := CompareVersions(c.b, c.a); got != -c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d (antisymmetry)", c.b, c.a, got, -c.want)
		}
	}
}

func TestRangeMatch(t *testing.T) {
	cases := []struct {
		name string
		r    Range
		v    string
		full int
		want MatchResult
	}{
		// CVE-2021-41773: Apache httpd 2.4.49 only (NVD lists it as an exact version).
		{"exact hit", Range{Exact: "2.4.49"}, "2.4.49", 3, Match},
		{"exact miss", Range{Exact: "2.4.49"}, "2.4.50", 3, NoMatch},
		{"end excluding hit", Range{EE: "2.4.50"}, "2.4.29", 3, Match},
		{"end excluding boundary", Range{EE: "2.4.50"}, "2.4.50", 3, NoMatch},
		{"end including boundary", Range{EI: "2.4.50"}, "2.4.50", 3, Match},
		{"start including boundary", Range{SI: "4.7", EE: "4.7.19"}, "4.7", 2, Match},
		{"start excluding boundary", Range{SE: "4.7", EE: "4.7.19"}, "4.7", 2, NoMatch},
		{"below start", Range{SI: "4.8", EE: "4.8.5"}, "4.7.5", 2, NoMatch},
		{"double digit patch", Range{SI: "4.7", EE: "4.7.19"}, "4.7.5", 2, Match},
		{"double digit patch above", Range{SI: "4.7", EE: "4.7.19"}, "4.7.20", 2, NoMatch},
		// CVE-2024-6387 regreSSHion: 8.5p1 <= v < 9.8p1.
		{"openssh in range", Range{SI: "8.5p1", EE: "9.8p1"}, "8.9p1", 2, Match},
		{"openssh fixed", Range{SI: "8.5p1", EE: "9.8p1"}, "9.8p1", 2, NoMatch},
		{"openssh too old", Range{SI: "8.5p1", EE: "9.8p1"}, "8.4p1", 2, NoMatch},
		// Incomplete versions: "nginx 1.18" stands for 1.18.0 .. 1.18.x.
		{"partial overlap", Range{EE: "1.18.2"}, "1.18", 3, PossibleMatch},
		{"partial fully inside", Range{SI: "1.17.0", EE: "1.20.0"}, "1.18", 3, Match},
		{"partial fully below", Range{SI: "1.19.0", EE: "1.20.0"}, "1.18", 3, NoMatch},
		{"partial above end", Range{EE: "1.18.0"}, "1.18", 3, NoMatch},
		{"partial exact", Range{Exact: "1.18.1"}, "1.18", 3, PossibleMatch},
		{"partial exact other branch", Range{Exact: "1.180.1"}, "1.18", 3, NoMatch},
		{"no bounds", Range{}, "1.0", 2, NoMatch},
		{"garbage version", Range{EE: "2.0"}, "unknown", 2, NoMatch},
		{"pre-release before fix", Range{EE: "3.0.0"}, "3.0.0-rc1", 3, Match},
	}
	for _, c := range cases {
		if got := c.r.matchVersion(c.v, c.full); got != c.want {
			t.Errorf("%s: %s matchVersion(%q) = %d, want %d", c.name, c.r, c.v, got, c.want)
		}
	}
}

func TestLookupDef(t *testing.T) {
	cases := map[string]string{
		"nginx":                           "nginx",
		"Apache httpd":                    "apache-httpd",
		"Apache Tomcat/Coyote JSP engine": "tomcat",
		"Redis key-value store":           "redis",
		"PostgreSQL DB":                   "postgresql",
		"Microsoft IIS httpd":             "iis",
		"WordPress":                       "wordpress",
		"Dovecot imapd":                   "dovecot",
		"Joomla!":                         "joomla",
		"Apache":                          "apache-httpd",
	}
	for in, want := range cases {
		d := lookupDef(in)
		if d == nil || d.Key != want {
			t.Errorf("lookupDef(%q) = %v, want %s", in, d, want)
		}
	}
	if d := lookupDef("Moodle"); d != nil {
		t.Errorf("lookupDef(Moodle) = %s, want nil", d.Key)
	}
}

func TestSplitCPE(t *testing.T) {
	vp, ver, upd, ok := cpeVendorProduct(`cpe:2.3:a:joomla:joomla\!:3.4.1:*:*:*:*:*:*:*`)
	if !ok || unescapeCPE(vp) != "a:joomla:joomla!" || ver != "3.4.1" || upd != "*" {
		t.Fatalf("got %q %q %q %v", vp, ver, upd, ok)
	}
	if joinUpdate("8.9", "p1") != "8.9p1" || joinUpdate("3.0.0", "rc1") != "3.0.0-rc1" || joinUpdate("1.2", "*") != "1.2" {
		t.Fatal("joinUpdate")
	}
}
