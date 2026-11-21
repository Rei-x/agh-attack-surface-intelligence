package db

import (
	"testing"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/vulndb"
)

const vulnFixture = `{"schema":1,"generated_at":"2026-11-21T00:00:00Z",
 "cves":[
  {"id":"CVE-2021-41773","s":7.5,"sev":"HIGH","k":"2021-11-03","e":0.944,"ep":0.9995},
  {"id":"CVE-2021-42013","s":9.8,"sev":"CRITICAL","k":"2021-11-03","e":0.94,"ep":0.999},
  {"id":"CVE-2017-0002","s":6.1,"sev":"MEDIUM","e":0.02,"ep":0.6}],
 "products":{
  "apache-httpd":[{"c":"CVE-2021-41773","r":[{"x":"2.4.49"}]},{"c":"CVE-2021-42013","r":[{"x":"2.4.49"},{"x":"2.4.50"}]}],
  "wordpress":[{"c":"CVE-2017-0002","r":[{"ee":"4.7.19"}]}]}}`

func TestQueryVulnTerms(t *testing.T) {
	snap, err := vulndb.Parse([]byte(vulnFixture))
	if err != nil {
		t.Fatal(err)
	}
	vulndb.SetCurrent(vulndb.New(snap, "test"))
	defer vulndb.SetCurrent(nil)

	apache := &domain.Service{Port: 80, Product: "Apache httpd", Version: "2.4.49"}
	wp := &domain.Service{Port: 8088, Technologies: []domain.DetectedTechnology{{Name: "WordPress", Version: "4.7"}}}
	clean := &domain.Service{Port: 80, Product: "Apache httpd", Version: "2.4.62"}
	cases := map[string][3]bool{ // apache, wordpress, clean
		"cve:CVE-2021-41773": {true, false, false},
		"cve:cve-2017-0002":  {false, true, false},
		"cve:true":           {true, true, false},
		"vuln:true":          {true, true, false},
		"kev:true":           {true, false, false},
		"-kev:true":          {false, true, true},
		"epss>0.5":           {true, false, false},
		"epss:>=0.01":        {true, true, false},
		"epss>50%":           {true, false, false},
		"cvss>=9":            {true, false, false},
		"cvss>=6":            {true, true, false},
		"cvss<7":             {false, true, false},
		"verified:true":      {false, false, false},
		"kev:true port:80":   {true, false, false},
	}
	for q, want := range cases {
		pq, err := ParseAssetQuery(q)
		if err != nil {
			t.Fatalf("%s: %v", q, err)
		}
		for i, s := range []*domain.Service{apache, wp, clean} {
			if got := pq.MatchService(s); got != want[i] {
				t.Errorf("%s on service %d: got %v want %v", q, i, got, want[i])
			}
		}
	}
	host := &domain.Host{IP: "10.0.0.5", Services: []domain.Service{*clean, *apache}}
	if pq, _ := ParseAssetQuery("kev:true"); !pq.MatchHost(host) {
		t.Error("kev:true should match a host with one KEV service")
	}
	for _, bad := range []string{"epss>abc", "kev:maybe", "cvss:>=x"} {
		if _, err := ParseAssetQuery(bad); err == nil {
			t.Errorf("%s must be rejected", bad)
		}
	}
}
