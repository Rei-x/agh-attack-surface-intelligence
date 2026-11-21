package ingest

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// Limits applied to imported / manually entered observations.
const (
	maxFieldLen   = 4096
	maxBannerLen  = 16 << 10
	maxListItems  = 256
	maxSvcPerHost = 4096
)

// ErrNoValidHosts is returned when nothing in an import survives validation.
var ErrNoValidHosts = errors.New("brak poprawnych hostów: kolumna/pole 'ip' musi zawierać adres IPv4 lub IPv6 / no valid hosts: the 'ip' field must hold an IPv4 or IPv6 address")

// DecodeText converts UTF-16 input (Excel "Unicode text" export, detected by its BOM) to
// UTF-8 and drops a UTF-8 BOM; other input is returned unchanged.
func DecodeText(raw []byte) []byte {
	switch {
	case len(raw) >= 2 && (raw[0] == 0xFF && raw[1] == 0xFE || raw[0] == 0xFE && raw[1] == 0xFF):
		be := raw[0] == 0xFE
		u := make([]uint16, 0, len(raw)/2)
		for i := 2; i+1 < len(raw); i += 2 {
			if be {
				u = append(u, uint16(raw[i])<<8|uint16(raw[i+1]))
			} else {
				u = append(u, uint16(raw[i+1])<<8|uint16(raw[i]))
			}
		}
		return []byte(string(utf16.Decode(u)))
	case bytes.HasPrefix(raw, []byte("\xEF\xBB\xBF")):
		return raw[3:]
	}
	return raw
}

// StripNUL removes NUL bytes and JSON-escaped NULs (\u0000) from raw import data. PostgreSQL
// rejects NUL in TEXT/JSONB, and no legitimate inventory field contains one.
func StripNUL(raw []byte) []byte {
	if bytes.IndexByte(raw, 0) >= 0 {
		raw = bytes.ReplaceAll(raw, []byte{0}, nil)
	}
	if bytes.Contains(raw, []byte(`\u0000`)) {
		raw = bytes.ReplaceAll(raw, []byte(`\u0000`), nil)
	}
	return raw
}

// NormalizeIP returns the canonical form of an IPv4/IPv6 address ("" if invalid).
// IPv4-mapped IPv6 is unmapped and zones are dropped.
func NormalizeIP(raw string) string {
	addr, err := netip.ParseAddr(strings.Trim(strings.TrimSpace(raw), "[]"))
	if err != nil {
		return ""
	}
	return addr.Unmap().WithZone("").String()
}

func cleanStr(s string, max int) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	s = strings.ReplaceAll(strings.TrimSpace(s), "\x00", "")
	if len(s) > max {
		s = s[:max]
		for !utf8.ValidString(s) { // do not cut a multi-byte rune in half
			s = s[:len(s)-1]
		}
	}
	return s
}

func cleanList(in []string) []string {
	if len(in) == 0 {
		return in
	}
	out := make([]string, 0, len(in))
	seen := make(map[string]bool, len(in))
	for _, v := range in {
		v = cleanStr(v, 256)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
		if len(out) >= maxListItems {
			break
		}
	}
	return out
}

// SanitizeObservations validates and normalizes observations from imports and manual entry:
// IPs must parse (and are canonicalized), ports must be 1-65535, protocols tcp/udp/sctp,
// strings are made valid UTF-8 and length-capped, duplicate hosts/services are merged.
// It returns the valid hosts and the number of skipped records.
func SanitizeObservations(in []domain.ObservedHost) ([]domain.ObservedHost, int, error) {
	out := make([]domain.ObservedHost, 0, len(in))
	index := make(map[string]int, len(in))
	skipped := 0
	for _, h := range in {
		ip := NormalizeIP(h.IP)
		if ip == "" {
			skipped++
			continue
		}
		h.IP = ip
		h.Hostname = cleanStr(h.Hostname, 253)
		h.OSGuess = cleanStr(h.OSGuess, 256)
		h.Environment = cleanStr(h.Environment, 64)
		h.Notes = cleanStr(h.Notes, maxFieldLen)
		h.Domains = cleanList(h.Domains)
		h.Tags = cleanList(h.Tags)

		svcs := make([]domain.ObservedService, 0, len(h.Services))
		for _, s := range h.Services {
			if s.Port < 1 || s.Port > 65535 {
				skipped++
				continue
			}
			s.Protocol = strings.ToLower(strings.TrimSpace(s.Protocol))
			switch s.Protocol {
			case "tcp", "udp", "sctp":
			case "":
				s.Protocol = "tcp"
			default:
				skipped++
				continue
			}
			s.State = cleanStr(strings.ToLower(s.State), 32)
			if s.State == "" {
				s.State = "open"
			}
			s.ServiceName = cleanStr(s.ServiceName, 128)
			s.Product = cleanStr(s.Product, 256)
			s.Version = cleanStr(s.Version, 128)
			s.CPE = cleanStr(s.CPE, 512)
			s.Banner = cleanStr(s.Banner, maxBannerLen)
			s.Notes = cleanStr(s.Notes, maxFieldLen)
			s.Tags = cleanList(s.Tags)
			if s.HTTP != nil {
				fp := *s.HTTP
				fp.URL = cleanStr(fp.URL, 2048)
				fp.Title = cleanStr(fp.Title, 512)
				fp.ServerHeader = cleanStr(fp.ServerHeader, 512)
				fp.BodySnippet = cleanStr(fp.BodySnippet, maxBannerLen)
				if fp.StatusCode < 0 || fp.StatusCode > 999 {
					fp.StatusCode = 0
				}
				if len(fp.Headers) > maxListItems {
					fp.Headers = nil
				}
				s.HTTP = &fp
			}
			svcs = append(svcs, s)
		}
		h.Services = dedupeServices(svcs)
		if len(h.Services) > maxSvcPerHost {
			skipped += len(h.Services) - maxSvcPerHost
			h.Services = h.Services[:maxSvcPerHost]
		}

		if i, ok := index[ip]; ok { // same IP twice (duplicate rows): merge
			prev := &out[i]
			prev.Services = dedupeServices(append(prev.Services, h.Services...))
			prev.Tags = cleanList(append(prev.Tags, h.Tags...))
			prev.Domains = cleanList(append(prev.Domains, h.Domains...))
			if prev.Hostname == "" {
				prev.Hostname = h.Hostname
			}
			prev.IsAlive = prev.IsAlive || h.IsAlive
			continue
		}
		index[ip] = len(out)
		out = append(out, h)
	}
	if len(out) == 0 {
		if skipped > 0 {
			return nil, skipped, fmt.Errorf("%w (odrzucono %d rekordów / %d records rejected)", ErrNoValidHosts, skipped, skipped)
		}
		return nil, 0, ErrNoValidHosts
	}
	return out, skipped, nil
}

// dedupeServices keeps one entry per port/protocol (the last one wins, as a later row in an
// import is the more recent observation).
func dedupeServices(in []domain.ObservedService) []domain.ObservedService {
	if len(in) < 2 {
		return in
	}
	pos := make(map[string]int, len(in))
	out := make([]domain.ObservedService, 0, len(in))
	for _, s := range in {
		k := svcKey(s.Port, s.Protocol)
		if i, ok := pos[k]; ok {
			out[i] = s
			continue
		}
		pos[k] = len(out)
		out = append(out, s)
	}
	return out
}
