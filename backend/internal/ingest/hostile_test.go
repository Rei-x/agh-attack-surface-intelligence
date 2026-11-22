package ingest

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

func TestParseCSVExcelPolishExport(t *testing.T) {
	// Excel (pl-PL): BOM, "sep=;" line, ';' delimiter, CRLF, quoted field with ';' inside.
	in := "\ufeffsep=;\r\nIP;Port;Protocol;Service;Notes\r\n10.0.0.1;22;tcp;ssh;\"a;b\"\r\n10.0.0.1;80;tcp;http;\r\n"
	hosts, err := ParseCSV(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || len(hosts[0].Services) != 2 || hosts[0].Services[0].Notes != "a;b" {
		t.Fatalf("unexpected parse: %+v", hosts)
	}
}

func TestParseCSVSemicolonWithoutSepLineAndTabs(t *testing.T) {
	for name, in := range map[string]string{
		"semicolon":   "ip;port\n10.0.0.2;443\n",
		"tab":         "ip\tport\n10.0.0.2\t443\n",
		"stray quote": "ip,port,notes\n10.0.0.2,443,he said \"hi\n",
	} {
		hosts, err := ParseCSV(strings.NewReader(in))
		if err != nil || len(hosts) != 1 || len(hosts[0].Services) != 1 || hosts[0].Services[0].Port != 443 {
			t.Errorf("%s: %v %+v", name, err, hosts)
		}
	}
}

func TestDecodeTextUTF16Excel(t *testing.T) {
	text := "ip\tport\r\n10.0.0.3\t22\r\n"
	u := utf16.Encode([]rune(text))
	raw := []byte{0xFF, 0xFE}
	for _, c := range u {
		raw = append(raw, byte(c), byte(c>>8))
	}
	hosts, err := ParseCSV(bytes.NewReader(DecodeText(raw)))
	if err != nil || len(hosts) != 1 || hosts[0].IP != "10.0.0.3" {
		t.Fatalf("utf-16 csv: %v %+v", err, hosts)
	}
}

func TestSanitizeObservationsRejectsGarbage(t *testing.T) {
	in := []domain.ObservedHost{
		{IP: "not-an-ip"},
		{IP: "<script>alert(1)</script>"},
		{IP: " 10.0.0.1 ", Hostname: "a\x00b", Services: []domain.ObservedService{
			{Port: 0}, {Port: 70000}, {Port: -1}, {Port: 22, Protocol: "TCP"}, {Port: 22, Protocol: "tcp", Product: "dup"}, {Port: 53, Protocol: "bogus"},
		}},
		{IP: "::ffff:10.0.0.1", Services: []domain.ObservedService{{Port: 80}}}, // same host, mapped
		{IP: "fe80::1%eth0", Notes: strings.Repeat("x", 100000) + "\xff"},
	}
	out, skipped, err := SanitizeObservations(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("want 2 hosts (dup merged), got %d: %+v", len(out), out)
	}
	h := out[0]
	if h.IP != "10.0.0.1" || h.Hostname != "ab" || len(h.Services) != 2 {
		t.Fatalf("host not normalized: %+v", h)
	}
	if h.Services[0].Product != "dup" {
		t.Fatalf("duplicate port row should keep the last observation: %+v", h.Services)
	}
	if out[1].IP != "fe80::1" || len(out[1].Notes) > maxFieldLen || !utf8.ValidString(out[1].Notes) {
		t.Fatalf("ipv6 host not cleaned: ip=%q notes=%d", out[1].IP, len(out[1].Notes))
	}
	if skipped != 6 { // 2 bad IPs + ports 0/70000/-1 + bogus protocol
		t.Fatalf("skipped=%d, want 6", skipped)
	}
	if _, _, err := SanitizeObservations([]domain.ObservedHost{{IP: "x"}}); !errors.Is(err, ErrNoValidHosts) {
		t.Fatalf("all-invalid import must fail with ErrNoValidHosts, got %v", err)
	}
}

func TestParseJSONOversizedIsAnErrorNotTruncation(t *testing.T) {
	big := bytes.Repeat([]byte(" "), int(MaxImportBytes)+1)
	if _, err := ParseJSON(bytes.NewReader(big)); !errors.Is(err, ErrImportTooLarge) {
		t.Fatalf("got %v, want ErrImportTooLarge", err)
	}
}

func TestParseJSONDeepNestingFailsCleanly(t *testing.T) {
	deep := strings.Repeat(`{"hosts":`, 20000) + "[]" + strings.Repeat("}", 20000)
	if _, err := ParseJSON(strings.NewReader(deep)); err == nil {
		t.Fatal("expected an error for absurdly nested JSON")
	}
	arr := strings.Repeat("[", 100000) + strings.Repeat("]", 100000)
	if _, err := ParseJSON(strings.NewReader(arr)); err == nil {
		t.Fatal("expected an error for nested arrays")
	}
}

func TestStripNUL(t *testing.T) {
	got := string(StripNUL([]byte("a\x00b\\u0000c")))
	if got != "abc" {
		t.Fatalf("got %q", got)
	}
}

// The fuzz targets check that parsers never panic or hang on arbitrary input.

func FuzzParseCSV(f *testing.F) {
	f.Add([]byte("ip,port\n10.0.0.1,22\n"))
	f.Add([]byte("\ufeffsep=;\r\nip;port;http_title;headers\r\n10.0.0.1;80;x;a:b;c:d\r\n"))
	f.Add([]byte("ip\n\"unterminated"))
	f.Add([]byte{0xFF, 0xFE, 'i', 0, 'p', 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		hosts, err := ParseCSV(bytes.NewReader(StripNUL(DecodeText(data))))
		if err == nil {
			_, _, _ = SanitizeObservations(hosts)
		}
	})
}

func FuzzParseJSON(f *testing.F) {
	f.Add([]byte(`[{"ip":"10.0.0.1","port":22}]`))
	f.Add([]byte(`{"hosts":[{"ip":"10.0.0.1","services":[{"port":80,"http":{"title":"x"}}]}]}`))
	f.Add([]byte(`{"data":{"items":{"hosts":null}}}`))
	f.Add([]byte(`[{"ip":"::1","port":1e30,"tags":[1,{"a":2}],"headers":{"x":[1]}}]`))
	f.Fuzz(func(t *testing.T, data []byte) {
		hosts, err := ParseJSON(bytes.NewReader(StripNUL(data)))
		if err == nil {
			out, _, err := SanitizeObservations(hosts)
			if err == nil {
				for _, h := range out {
					if NormalizeIP(h.IP) != h.IP {
						t.Fatalf("non-canonical IP survived: %q", h.IP)
					}
					for _, s := range h.Services {
						if s.Port < 1 || s.Port > 65535 {
							t.Fatalf("invalid port survived: %d", s.Port)
						}
					}
				}
			}
		}
	})
}
