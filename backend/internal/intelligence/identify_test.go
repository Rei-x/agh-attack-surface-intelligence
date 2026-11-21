package intelligence

import (
	"testing"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

func TestParseServerHeaderRealServers(t *testing.T) {
	cases := []struct{ header, product, version string }{
		{"nginx/1.24.0", "nginx", "1.24.0"},
		{"nginx/1.18.0 (Ubuntu)", "nginx", "1.18.0"},
		{"nginx", "nginx", ""},
		{"Apache/2.4.52 (Ubuntu)", "Apache httpd", "2.4.52"},
		{"Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips PHP/7.4.33", "Apache httpd", "2.4.6"},
		{"Apache", "Apache httpd", ""},
		{"Apache-Coyote/1.1", "Apache Tomcat/Coyote JSP engine", "1.1"},
		{"Microsoft-IIS/10.0", "Microsoft IIS httpd", "10.0"},
		{"Microsoft-HTTPAPI/2.0", "Microsoft HTTPAPI httpd", "2.0"},
		{"Jetty(9.4.50.v20221201)", "Jetty", "9.4.50"},
		{"Jetty(10.0.18)", "Jetty", "10.0.18"},
		{"CUPS/2.4 IPP/2.1", "CUPS", "2.4"},
		{"WSGIServer/0.2 CPython/3.10.12", "WSGIServer", "0.2"},
		{"Werkzeug/2.3.7 Python/3.11.4", "Werkzeug httpd", "2.3.7"},
		{"debut/1.30", "Debut embedded httpd", "1.30"},
		{"HP HTTP Server; HP Color LaserJet MFP M479fdw - W1A79A; Serial Number: CNBRM12345; Built: Mon Nov 07, 2022", "HP HTTP Server", ""},
		{"lighttpd/1.4.59", "lighttpd", "1.4.59"},
		{"openresty/1.21.4.1", "OpenResty web app server", "1.21.4.1"},
		{"webserver", "", ""},
		{"", "", ""},
	}
	for _, c := range cases {
		p, v := ParseServerHeader(c.header)
		if p != c.product || v != c.version {
			t.Errorf("ParseServerHeader(%q) = %q %q; want %q %q", c.header, p, v, c.product, c.version)
		}
	}
}

func TestParseCPE(t *testing.T) {
	cases := []struct{ cpe, product, version string }{
		{"cpe:/a:igor_sysoev:nginx:1.24.0", "nginx", "1.24.0"},
		{"cpe:/a:apache:http_server:2.4.52", "Apache httpd", "2.4.52"},
		{"cpe:/a:microsoft:internet_information_services:10.0", "Microsoft IIS httpd", "10.0"},
		{"cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*", "OpenSSH", "8.9p1"},
		{"cpe:/a:apache:tomcat:9.0.83", "Apache Tomcat", "9.0.83"},
		{"cpe:/a:acme:widget_server", "Widget Server", ""},
		{"cpe:/o:linux:linux_kernel", "", ""},
	}
	for _, c := range cases {
		p, v := ParseCPE(c.cpe)
		if p != c.product || v != c.version {
			t.Errorf("ParseCPE(%q) = %q %q; want %q %q", c.cpe, p, v, c.product, c.version)
		}
	}
}

func TestIdentifyProductPrecedence(t *testing.T) {
	// nmap identified the product: keep it, but fill a missing version from the Server header.
	id := IdentifyProduct(domain.ObservedService{
		Port: 80, ServiceName: "http", Product: "nginx",
		HTTP: &domain.HTTPFingerprint{ServerHeader: "nginx/1.24.0"},
	})
	if id.Product != "nginx" || id.Version != "1.24.0" || id.Source != SourceNmap || id.VersionSource != SourceServerHeader {
		t.Fatalf("nginx version fill: %+v", id)
	}

	// nmap was generic (no product): the Server header names the server.
	id = IdentifyProduct(domain.ObservedService{
		Port: 443, ServiceName: "https",
		HTTP: &domain.HTTPFingerprint{ServerHeader: "Apache/2.4.57 (Debian)"},
	})
	if id.Product != "Apache httpd" || id.Version != "2.4.57" || id.Source != SourceServerHeader {
		t.Fatalf("server header fallback: %+v", id)
	}

	// Tomcat >= 8.5 sends no Server header; its default page names it.
	id = IdentifyProduct(domain.ObservedService{
		Port: 8080, ServiceName: "http-proxy",
		HTTP: &domain.HTTPFingerprint{Title: "Apache Tomcat/9.0.83"},
	})
	if id.Product != "Apache Tomcat" || id.Version != "9.0.83" || id.Source != SourceHTTPPage {
		t.Fatalf("tomcat page: %+v", id)
	}

	// nmap's product wins over a conflicting header (reverse proxies rewrite headers).
	id = IdentifyProduct(domain.ObservedService{
		Port: 80, ServiceName: "http", Product: "Apache httpd", Version: "2.4.52",
		HTTP: &domain.HTTPFingerprint{ServerHeader: "nginx/1.24.0"},
	})
	if id.Product != "Apache httpd" || id.Version != "2.4.52" {
		t.Fatalf("nmap precedence: %+v", id)
	}

	// Names are normalised to nmap's spelling.
	id = IdentifyProduct(domain.ObservedService{Port: 80, ServiceName: "http", Product: "Apache HTTP Server"})
	if id.Product != "Apache httpd" {
		t.Fatalf("normalise: %+v", id)
	}

	// CPE only (e.g. imported XML without product attribute).
	id = IdentifyProduct(domain.ObservedService{Port: 22, ServiceName: "ssh", CPE: "cpe:/a:openbsd:openssh:9.6p1"})
	if id.Product != "OpenSSH" || id.Version != "9.6p1" || id.Source != SourceCPE {
		t.Fatalf("cpe: %+v", id)
	}
}
