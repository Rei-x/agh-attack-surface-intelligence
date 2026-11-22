package db

import "github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"

// maxSnapshotBanner bounds a banner kept in a scan snapshot or a slimmed observation. nmap
// banners are short; this only stops a pathological service from bloating every snapshot.
const maxSnapshotBanner = 1024

// SlimSnapshotHosts returns the per-run inventory snapshot that SaveScanSnapshot stores.
//
// A snapshot is a copy of the whole inventory taken after every run, used by the scan diff
// (UI and `dzieciol diff`) and `dzieciol export --scan`. A full copy repeats every HTTP
// fingerprint (headers, cookies, body snippet, TLS chain, safe-path hits), technology
// evidence and the availability model of every host, which made snapshots more than 80% of
// a long-running store. The slim copy keeps what the diff compares and shows (host identity,
// lifecycle state, owner, ports, product/version, banner, admin flag, HTTP title, status and
// response time) plus the cheap descriptive fields an export of an older run needs.
func SlimSnapshotHosts(hosts []domain.Host) []domain.Host {
	out := make([]domain.Host, len(hosts))
	for i := range hosts {
		h := &hosts[i]
		sh := domain.Host{
			ID:                h.ID,
			IP:                h.IP,
			Hostname:          h.Hostname,
			Domains:           h.Domains,
			OSGuess:           h.OSGuess,
			LifecycleState:    h.LifecycleState,
			Environment:       h.Environment,
			Owner:             h.Owner,
			Tags:              h.Tags,
			FirstSeen:         h.FirstSeen,
			LastSeen:          h.LastSeen,
			TotalScansSeen:    h.TotalScansSeen,
			TotalScansChecked: h.TotalScansChecked,
			ConsecutiveMisses: h.ConsecutiveMisses,
			StateTransitions:  h.StateTransitions,
			StabilityScore:    h.StabilityScore,
			Interestingness:   h.Interestingness,
			ServiceCount:      h.ServiceCount,
			TriageStatus:      h.TriageStatus,
		}
		if len(h.Services) > 0 {
			sh.Services = make([]domain.Service, len(h.Services))
			for j := range h.Services {
				sh.Services[j] = slimSnapshotService(&h.Services[j])
			}
		}
		if sh.ServiceCount == 0 {
			sh.ServiceCount = len(h.Services)
		}
		out[i] = sh
	}
	return out
}

func slimSnapshotService(s *domain.Service) domain.Service {
	techs := make([]domain.DetectedTechnology, 0, len(s.Technologies))
	for _, t := range s.Technologies {
		techs = append(techs, domain.DetectedTechnology{Name: t.Name, Category: t.Category, Version: t.Version, Confidence: t.Confidence})
	}
	return domain.Service{
		ID:                s.ID,
		HostID:            s.HostID,
		HostIP:            s.HostIP,
		Port:              s.Port,
		Protocol:          s.Protocol,
		State:             s.State,
		ServiceName:       s.ServiceName,
		Product:           s.Product,
		Version:           s.Version,
		ProductSource:     s.ProductSource,
		VersionSource:     s.VersionSource,
		CPE:               s.CPE,
		Banner:            truncateBanner(s.Banner),
		HTTP:              SlimHTTP(s.HTTP),
		Technologies:      techs,
		MatchedSignatures: s.MatchedSignatures,
		IsAdminPanel:      s.IsAdminPanel,
		IsStagingEnv:      s.IsStagingEnv,
		IsIoT:             s.IsIoT,
		Interestingness:   s.Interestingness,
		TriageStatus:      s.TriageStatus,
		Tags:              s.Tags,
		FirstSeen:         s.FirstSeen,
		LastSeen:          s.LastSeen,
	}
}

func truncateBanner(b string) string {
	if len(b) <= maxSnapshotBanner {
		return b
	}
	return b[:maxSnapshotBanner]
}

// SlimHTTP keeps the identifying part of an HTTP fingerprint: URL, status, title, server
// header, favicon hash, response times and the certificate identity. Headers, cookies,
// redirect chain, body snippet and safe-path hits are dropped. It is used for scan snapshots
// and for older observations (the evidence history shows title, product and version).
func SlimHTTP(fp *domain.HTTPFingerprint) *domain.HTTPFingerprint {
	if fp == nil {
		return nil
	}
	out := &domain.HTTPFingerprint{
		URL:              fp.URL,
		Scheme:           fp.Scheme,
		StatusCode:       fp.StatusCode,
		Title:            fp.Title,
		ServerHeader:     fp.ServerHeader,
		FaviconMMH3:      fp.FaviconMMH3,
		MetaGenerator:    fp.MetaGenerator,
		FooterVersion:    fp.FooterVersion,
		LoginForm:        fp.LoginForm,
		CatchAll:         fp.CatchAll,
		ResponseTimeMs:   fp.ResponseTimeMs,
		MedianResponseMs: fp.MedianResponseMs,
		ResponseSamples:  fp.ResponseSamples,
	}
	if fp.TLS != nil {
		out.TLS = &domain.TLSInfo{
			Version:      fp.TLS.Version,
			SubjectCN:    fp.TLS.SubjectCN,
			Issuer:       fp.TLS.Issuer,
			NotAfter:     fp.TLS.NotAfter,
			DaysToExpiry: fp.TLS.DaysToExpiry,
			IsSelfSigned: fp.TLS.IsSelfSigned,
			IsExpired:    fp.TLS.IsExpired,
			SHA256:       fp.TLS.SHA256,
		}
	}
	return out
}
