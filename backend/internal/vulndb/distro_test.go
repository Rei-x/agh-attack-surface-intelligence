package vulndb

import (
	"testing"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// Banner strings as nmap -sV (version + extrainfo), SSH identification strings and HTTP
// headers print them on real hosts.
func TestParseDistroPackage(t *testing.T) {
	for _, tc := range []struct {
		name, product, version, context string
		want                            *domain.DistroPackage // nil: upstream build
	}{
		{"nmap Debian 12", "openssh", "9.2p1 Debian 2+deb12u3", "protocol 2.0",
			&domain.DistroPackage{Distro: "Debian", Release: "12", Codename: "bookworm", Revision: "2+deb12u3", Upstream: "9.2p1", Label: "Debian 12"}},
		{"nmap Debian 13 release package", "openssh", "10.0p1 Debian 7", "protocol 2.0",
			&domain.DistroPackage{Distro: "Debian", Release: "13", Codename: "trixie", Revision: "7", Upstream: "10.0p1", ReleaseInferred: true, Label: "Debian 13"}},
		{"nmap Debian 9", "openssh", "7.4p1 Debian 10+deb9u7", "protocol 2.0",
			&domain.DistroPackage{Distro: "Debian", Release: "9", Codename: "stretch", Revision: "10+deb9u7", Upstream: "7.4p1", Label: "Debian 9"}},
		{"nmap Ubuntu 22.04", "openssh", "8.9p1 Ubuntu 3ubuntu0.10", "Ubuntu Linux; protocol 2.0",
			&domain.DistroPackage{Distro: "Ubuntu", Release: "22.04", Codename: "jammy", Revision: "3ubuntu0.10", Upstream: "8.9p1", ReleaseInferred: true, Label: "Ubuntu 22.04"}},
		{"SSH banner Ubuntu 20.04", "openssh", "8.2p1 Ubuntu-4ubuntu0.11", "",
			&domain.DistroPackage{Distro: "Ubuntu", Release: "20.04", Codename: "focal", Revision: "4ubuntu0.11", Upstream: "8.2p1", ReleaseInferred: true, Label: "Ubuntu 20.04"}},
		{"SSH banner Ubuntu 24.04", "openssh", "9.6p1 Ubuntu-3ubuntu13.5", "",
			&domain.DistroPackage{Distro: "Ubuntu", Release: "24.04", Codename: "noble", Revision: "3ubuntu13.5", Upstream: "9.6p1", ReleaseInferred: true, Label: "Ubuntu 24.04"}},
		{"SSH banner Ubuntu 14.04", "openssh", "6.6.1p1 Ubuntu 2ubuntu2.13", "Ubuntu Linux; protocol 2.0",
			&domain.DistroPackage{Distro: "Ubuntu", Release: "14.04", Codename: "trusty", Revision: "2ubuntu2.13", Upstream: "6.6.1p1", ReleaseInferred: true, Label: "Ubuntu 14.04"}},
		{"Raspberry Pi OS", "openssh", "7.9p1 Raspbian 10+deb10u2", "protocol 2.0",
			&domain.DistroPackage{Distro: "Raspbian", Release: "10", Codename: "buster", Revision: "10+deb10u2", Upstream: "7.9p1", Label: "Raspbian 10"}},
		{"RHEL family, rpm release", "openssh", "7.4p1-21.el7", "",
			&domain.DistroPackage{Distro: "Enterprise Linux", Release: "7", Codename: "el7", Revision: "21.el7", Upstream: "7.4p1", Label: "Enterprise Linux 7"}},
		{"RHEL family named in extrainfo", "openssh", "7.4", "RHEL/CentOS el7; protocol 2.0",
			&domain.DistroPackage{Distro: "CentOS", Release: "7", Codename: "el7", Upstream: "7.4", Label: "CentOS 7"}},
		{"nginx Server header (Ubuntu)", "nginx", "1.18.0", "nginx/1.18.0 (Ubuntu)",
			&domain.DistroPackage{Distro: "Ubuntu", Upstream: "1.18.0", Label: "Ubuntu"}},
		{"Apache Server header (Debian)", "apache-httpd", "2.4.57", "Apache/2.4.57 (Debian)",
			&domain.DistroPackage{Distro: "Debian", Upstream: "2.4.57", Label: "Debian"}},
		{"Apache Server header (Red Hat Enterprise Linux)", "apache-httpd", "2.4.37", "Apache/2.4.37 (Red Hat Enterprise Linux) OpenSSL/1.1.1k",
			&domain.DistroPackage{Distro: "RHEL", Upstream: "2.4.37", Label: "RHEL"}},
		{"Apache Server header (CentOS) with fips OpenSSL", "apache-httpd", "2.4.6", "Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/5.4.16",
			&domain.DistroPackage{Distro: "CentOS", Upstream: "2.4.6", Label: "CentOS"}},
		{"Apache Server header (Rocky Linux)", "apache-httpd", "2.4.57", "Apache/2.4.57 (Rocky Linux)",
			&domain.DistroPackage{Distro: "Rocky Linux", Upstream: "2.4.57", Label: "Rocky Linux"}},
		{"Apache Server header (Fedora Linux)", "apache-httpd", "2.4.58", "Apache/2.4.58 (Fedora Linux)",
			&domain.DistroPackage{Distro: "Fedora", Upstream: "2.4.58", Label: "Fedora"}},
		{"X-Powered-By PHP Ubuntu 20.04", "php", "7.4.3-4ubuntu2.19", "PHP/7.4.3-4ubuntu2.19",
			&domain.DistroPackage{Distro: "Ubuntu", Revision: "4ubuntu2.19", Upstream: "7.4.3", Label: "Ubuntu"}},
		{"X-Powered-By PHP Debian 12", "php", "8.2.28-1~deb12u1", "PHP/8.2.28-1~deb12u1",
			&domain.DistroPackage{Distro: "Debian", Release: "12", Codename: "bookworm", Revision: "1~deb12u1", Upstream: "8.2.28", Label: "Debian 12"}},
		{"MariaDB handshake Debian 12", "mariadb", "10.11.6-MariaDB-0+deb12u1", "",
			&domain.DistroPackage{Distro: "Debian", Release: "12", Codename: "bookworm", Revision: "0+deb12u1", Upstream: "10.11.6", Label: "Debian 12"}},
		{"MariaDB handshake Ubuntu 22.04", "mariadb", "10.6.16-MariaDB-0ubuntu0.22.04.1", "",
			&domain.DistroPackage{Distro: "Ubuntu", Release: "22.04", Codename: "jammy", Revision: "0ubuntu0.22.04.1", Upstream: "10.6.16", Label: "Ubuntu 22.04"}},
		{"MySQL handshake Ubuntu 22.04", "mysql", "8.0.36-0ubuntu0.22.04.1", "",
			&domain.DistroPackage{Distro: "Ubuntu", Release: "22.04", Codename: "jammy", Revision: "0ubuntu0.22.04.1", Upstream: "8.0.36", Label: "Ubuntu 22.04"}},
		// Upstream builds: nothing names a distribution.
		{"nginx upstream", "nginx", "1.20.1", "nginx/1.20.1", nil},
		{"OpenSSH upstream", "openssh", "9.8p1", "protocol 2.0", nil},
		{"RHEL sshd says nothing", "openssh", "7.4", "protocol 2.0", nil},
		{"Apache (Unix)", "apache-httpd", "2.4.62", "Apache/2.4.62 (Unix)", nil},
		{"IIS", "iis", "10.0", "Microsoft-IIS/10.0", nil},
		{"fips marker only", "openssl", "1.0.2k-fips", "", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseDistroPackage(tc.product, tc.version, tc.context)
			switch {
			case tc.want == nil && got != nil:
				t.Fatalf("upstream build parsed as %+v", *got)
			case tc.want != nil && got == nil:
				t.Fatalf("got nil, want %+v", *tc.want)
			case tc.want != nil && *got != *tc.want:
				t.Fatalf("got  %+v\nwant %+v", *got, *tc.want)
			}
		})
	}
}

func TestCompareDebianRevision(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"2+deb12u3", "2+deb12u3", 0},
		{"2+deb12u10", "2+deb12u3", 1},
		{"2+deb12u2", "2+deb12u3", -1},
		{"2", "2+deb12u3", -1}, // the release package predates every stable update
		{"3ubuntu0.10", "3ubuntu0.9", 1},
		{"3ubuntu0.5", "3ubuntu0.10", -1},
		{"3ubuntu13.5", "3ubuntu1", 1},
		{"1~deb12u1", "1", -1}, // "~" sorts before the end
		{"4ubuntu0.7+esm3", "4ubuntu0.7", 1},
		{"1:9.2p1-2+deb12u3", "1:9.2p1-2+deb12u3", 0},
	} {
		if got := compareDebianRevision(tc.a, tc.b); got != tc.want {
			t.Errorf("compare(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
		if got := compareDebianRevision(tc.b, tc.a); got != -tc.want {
			t.Errorf("compare(%q, %q) = %d, want %d", tc.b, tc.a, got, -tc.want)
		}
	}
}

// Header-sourced versions take the revision of their own token only.
func TestHeaderPackageRevision(t *testing.T) {
	svc := &domain.Service{Port: 80, ServiceName: "http",
		HTTP: &domain.HTTPFingerprint{ServerHeader: "Apache/2.4.52 (Ubuntu) PHP/8.1.2-1ubuntu2.14"}}
	for _, tc := range []struct{ version, wantVersion, wantCtx string }{
		{"2.4.52", "2.4.52", "Apache/2.4.52 (Ubuntu) PHP/8.1.2-1ubuntu2.14"},
		{"8.1.2", "8.1.2-1ubuntu2.14", "Apache/2.4.52 (Ubuntu) PHP/8.1.2-1ubuntu2.14"},
	} {
		v, ctx := packageEvidence(svc, candidate{version: tc.version, via: "http-server-header"})
		if v != tc.wantVersion || ctx != tc.wantCtx {
			t.Errorf("%s: %q, %q", tc.version, v, ctx)
		}
	}
	p := ParseDistroPackage("apache-httpd", "2.4.52", svc.HTTP.ServerHeader)
	if p == nil || p.Revision != "" || p.Label != "Ubuntu" {
		t.Fatalf("Apache took PHP's revision: %+v", p)
	}
}
