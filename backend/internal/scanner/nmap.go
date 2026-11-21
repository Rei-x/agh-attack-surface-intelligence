package scanner

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// NmapAvailable reports whether the nmap binary is installed on PATH.
func NmapAvailable() bool {
	_, err := exec.LookPath("nmap")
	return err == nil
}

// NmapRunner executes safe Nmap commands (host discovery & bounded service detection)
// with a pure-Go TCP connect/banner fallback when nmap is disabled or unavailable.
type NmapRunner struct {
	UseNmap           bool
	NmapBinary        string
	ConnectTimeout    time.Duration
	BannerReadTimeout time.Duration
	Concurrency       int
}

// NewNmapRunner returns a runner configured with safe timeouts.
func NewNmapRunner(useNmap bool) *NmapRunner {
	bin, err := exec.LookPath("nmap")
	if err != nil {
		useNmap = false
	}
	return &NmapRunner{
		UseNmap:           useNmap && bin != "",
		NmapBinary:        bin,
		ConnectTimeout:    1500 * time.Millisecond,
		BannerReadTimeout: 1200 * time.Millisecond,
		Concurrency:       32,
	}
}

// DiscoverHosts performs Stage 1 host discovery using `nmap -sn` when enabled,
// or pure-Go TCP probing across probePorts when nmap is unavailable/disabled.
func (r *NmapRunner) DiscoverHosts(ctx context.Context, ips []string, probePorts []int, maxRatePPS int, gov *Governor) ([]string, error) {
	if len(ips) == 0 {
		return nil, nil
	}
	if r.UseNmap && r.NmapBinary != "" {
		active, err := r.discoverWithNmap(ctx, ips, maxRatePPS)
		if err == nil {
			return active, nil
		}
		// Fallback to pure-Go if nmap execution fails (e.g. unprivileged sandbox).
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return r.discoverPureGo(ctx, ips, probePorts, gov)
}

func (r *NmapRunner) discoverWithNmap(ctx context.Context, ips []string, maxRatePPS int) ([]string, error) {
	if maxRatePPS <= 0 {
		maxRatePPS = 300
	}
	args := []string{
		"-sn",
		"-n",
		"--max-rate", strconv.Itoa(maxRatePPS),
		"-oX", "-",
	}
	args = append(args, ips...)

	cmd := exec.CommandContext(ctx, r.NmapBinary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("nmap -sn failed: %w (%s)", err, strings.TrimSpace(stderr.String()))
	}

	hosts, err := ParseNmapXML(stdout.Bytes())
	if err != nil {
		return nil, err
	}
	var alive []string
	for _, h := range hosts {
		if h.IsAlive && h.IP != "" {
			alive = append(alive, h.IP)
		}
	}
	sort.Strings(alive)
	return alive, nil
}

func (r *NmapRunner) discoverPureGo(ctx context.Context, ips []string, probePorts []int, gov *Governor) ([]string, error) {
	if len(probePorts) == 0 {
		probePorts = []int{80, 443, 22, 8080, 8443}
	}
	// Limit discovery probes per host to at most 6 ports for speed.
	checkPorts := probePorts
	if len(checkPorts) > 6 {
		checkPorts = checkPorts[:6]
	}

	workers := r.Concurrency
	if workers <= 0 {
		workers = 32
	}
	if workers > len(ips) {
		workers = len(ips)
	}

	timeout := r.ConnectTimeout
	if timeout <= 0 {
		timeout = 1200 * time.Millisecond
	}

	jobs := make(chan string, len(ips))
	for _, ip := range ips {
		jobs <- ip
	}
	close(jobs)

	var mu sync.Mutex
	var alive []string
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dialer := &net.Dialer{Timeout: timeout}
			for ip := range jobs {
				if ctx.Err() != nil {
					return
				}
				for _, port := range checkPorts {
					if ctx.Err() != nil {
						return
					}
					if gov != nil {
						if err := gov.Wait(ctx, ip); err != nil {
							return
						}
					}
					conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
					if err == nil {
						conn.Close()
						if gov != nil {
							gov.RecordSuccess(ip)
						}
						mu.Lock()
						alive = append(alive, ip)
						mu.Unlock()
						break
					}
					if gov != nil {
						classifyDialErr(gov, ip, err)
					}
				}
			}
		}()
	}
	wg.Wait()
	sort.Strings(alive)
	return alive, ctx.Err()
}

// ScanServices runs Stage 2 safe service/version detection strictly on activeIPs and allowed ports.
// Returns per-IP observed services AND a valid Nmap XML document (for DefectDojo import).
func (r *NmapRunner) ScanServices(ctx context.Context, activeIPs []string, ports []int, maxRatePPS int, gov *Governor) (map[string][]domain.ObservedService, string, error) {
	if len(activeIPs) == 0 || len(ports) == 0 {
		return map[string][]domain.ObservedService{}, "", nil
	}

	if r.UseNmap && r.NmapBinary != "" {
		res, xmlStr, err := r.scanWithNmap(ctx, activeIPs, ports, maxRatePPS)
		if err == nil {
			return res, xmlStr, nil
		}
		if ctx.Err() != nil {
			return nil, "", ctx.Err()
		}
	}
	return r.ScanServicesPureGo(ctx, activeIPs, ports, gov)
}

func (r *NmapRunner) scanWithNmap(ctx context.Context, activeIPs []string, ports []int, maxRatePPS int) (map[string][]domain.ObservedService, string, error) {
	if maxRatePPS <= 0 {
		maxRatePPS = 200
	}
	portStrs := make([]string, len(ports))
	for i, p := range ports {
		portStrs[i] = strconv.Itoa(p)
	}
	args := []string{
		"-sT",
		"-sV",
		"--version-intensity", "5",
		"-Pn",
		"-n",
		"-p", strings.Join(portStrs, ","),
		"--max-rate", strconv.Itoa(maxRatePPS),
		"-oX", "-",
	}
	args = append(args, activeIPs...)

	cmd := exec.CommandContext(ctx, r.NmapBinary, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, "", fmt.Errorf("nmap -sT -sV failed: %w (%s)", err, strings.TrimSpace(stderr.String()))
	}

	xmlBytes := stdout.Bytes()
	hosts, err := ParseNmapXML(xmlBytes)
	if err != nil {
		return nil, string(xmlBytes), err
	}

	out := make(map[string][]domain.ObservedService, len(hosts))
	for _, h := range hosts {
		out[h.IP] = h.Services
	}
	return out, string(xmlBytes), nil
}

// ScanServicesPureGo performs safe TCP connect + passive banner grab fallback and synthesizes valid Nmap XML.
func (r *NmapRunner) ScanServicesPureGo(ctx context.Context, activeIPs []string, ports []int, gov *Governor) (map[string][]domain.ObservedService, string, error) {
	startedAt := time.Now().UTC()

	type targetPort struct {
		ip   string
		port int
	}
	jobs := make(chan targetPort, len(activeIPs)*len(ports))
	for _, ip := range activeIPs {
		for _, port := range ports {
			jobs <- targetPort{ip: ip, port: port}
		}
	}
	close(jobs)

	workers := r.Concurrency
	if workers <= 0 {
		workers = 32
	}
	if workers > len(activeIPs)*len(ports) {
		workers = len(activeIPs) * len(ports)
	}
	if workers < 1 {
		workers = 1
	}

	connectTimeout := r.ConnectTimeout
	if connectTimeout <= 0 {
		connectTimeout = 1500 * time.Millisecond
	}
	bannerTimeout := r.BannerReadTimeout
	if bannerTimeout <= 0 {
		bannerTimeout = 800 * time.Millisecond
	}

	var mu sync.Mutex
	out := make(map[string][]domain.ObservedService, len(activeIPs))
	var wg sync.WaitGroup

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dialer := &net.Dialer{Timeout: connectTimeout}
			for job := range jobs {
				if ctx.Err() != nil {
					return
				}
				if gov != nil {
					if err := gov.Wait(ctx, job.ip); err != nil {
						return
					}
				}
				addr := net.JoinHostPort(job.ip, strconv.Itoa(job.port))
				conn, err := dialer.DialContext(ctx, "tcp", addr)
				if err != nil {
					if gov != nil {
						classifyDialErr(gov, job.ip, err)
					}
					continue
				}
				if gov != nil {
					gov.RecordSuccess(job.ip)
				}

				banner := readPassiveBanner(conn, bannerTimeout)
				conn.Close()

				svcName, product, version := inferServiceFromPortAndBanner(job.port, banner)
				svc := domain.ObservedService{
					Port:        job.port,
					Protocol:    "tcp",
					State:       "open",
					ServiceName: svcName,
					Product:     product,
					Version:     version,
					Banner:      banner,
				}
				mu.Lock()
				out[job.ip] = append(out[job.ip], svc)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	// Sort services deterministically per host.
	observedHosts := make([]domain.ObservedHost, 0, len(activeIPs))
	for _, ip := range activeIPs {
		svcs := out[ip]
		sort.Slice(svcs, func(i, j int) bool { return svcs[i].Port < svcs[j].Port })
		out[ip] = svcs
		observedHosts = append(observedHosts, domain.ObservedHost{
			IP:         ip,
			IsAlive:    true,
			ObservedAt: time.Now().UTC(),
			Services:   svcs,
		})
	}

	portStrs := make([]string, len(ports))
	for i, p := range ports {
		portStrs[i] = strconv.Itoa(p)
	}
	args := fmt.Sprintf("aegis-scanner -sT -sV -p %s", strings.Join(portStrs, ","))
	xmlStr := GenerateNmapXML(observedHosts, args, startedAt, time.Now().UTC())
	return out, xmlStr, ctx.Err()
}

func readPassiveBanner(conn net.Conn, timeout time.Duration) string {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if n <= 0 {
		return ""
	}
	return strings.TrimSpace(sanitizePrintable(string(buf[:n])))
}

func sanitizePrintable(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == '\n' || r == '\r' || r == '\t' || (r >= 32 && r <= 126) {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func inferServiceFromPortAndBanner(port int, banner string) (svcName, product, version string) {
	bl := strings.ToLower(banner)
	if strings.HasPrefix(banner, "SSH-") {
		svcName = "ssh"
		parts := strings.SplitN(banner, "-", 3)
		if len(parts) == 3 {
			fields := strings.Fields(parts[2])
			if len(fields) > 0 {
				pv := strings.SplitN(fields[0], "_", 2)
				product = pv[0]
				if len(pv) > 1 {
					version = pv[1]
				}
			}
		}
		return svcName, product, version
	}
	if strings.Contains(bl, "smtp") || port == 25 || port == 587 {
		return "smtp", "", ""
	}
	if strings.Contains(bl, "ftp") || port == 21 {
		return "ftp", "", ""
	}
	if strings.Contains(bl, "redis") || port == 6379 {
		return "redis", "Redis", ""
	}
	switch port {
	case 22:
		return "ssh", "", ""
	case 53:
		return "domain", "", ""
	case 80, 8000, 8080, 8081, 8888, 3000, 5000, 9000:
		return "http", "", ""
	case 443, 8443, 9443, 4443:
		return "https", "", ""
	case 3306:
		return "mysql", "MySQL", ""
	case 3389:
		return "ms-wbt-server", "", ""
	case 5432:
		return "postgresql", "PostgreSQL", ""
	case 9200:
		return "elasticsearch", "Elasticsearch", ""
	case 27017:
		return "mongodb", "MongoDB", ""
	default:
		return "unknown", "", ""
	}
}

func classifyDialErr(gov *Governor, host string, err error) {
	if err == nil {
		return
	}
	if errors.Is(err, context.DeadlineExceeded) {
		gov.RecordTimeout(host)
		return
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		gov.RecordTimeout(host)
		return
	}
	msg := strings.ToLower(err.Error())
	if strings.Contains(msg, "connection reset") {
		gov.RecordRST(host)
	}
}

// ==================== Pure-Go Nmap XML Parser & Aggregator ====================

type nmapRunXML struct {
	XMLName    xml.Name      `xml:"nmaprun"`
	Scanner    string        `xml:"scanner,attr"`
	Args       string        `xml:"args,attr"`
	Start      int64         `xml:"start,attr"`
	StartStr   string        `xml:"startstr,attr,omitempty"`
	Version    string        `xml:"version,attr"`
	XMLOutVer  string        `xml:"xmloutputversion,attr"`
	Hosts      []nmapHostXML `xml:"host"`
	RunStats   *nmapStatsXML `xml:"runstats,omitempty"`
}

type nmapHostXML struct {
	Status    nmapStatusXML    `xml:"status"`
	Addresses []nmapAddrXML    `xml:"address"`
	Hostnames nmapHostnamesXML `xml:"hostnames"`
	Ports     nmapPortsXML     `xml:"ports"`
	OS        *nmapOSXML       `xml:"os,omitempty"`
}

type nmapStatusXML struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr,omitempty"`
}

type nmapAddrXML struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapHostnamesXML struct {
	Hostnames []nmapHostnameXML `xml:"hostname"`
}

type nmapHostnameXML struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr,omitempty"`
}

type nmapPortsXML struct {
	Ports []nmapPortXML `xml:"port"`
}

type nmapPortXML struct {
	Protocol string          `xml:"protocol,attr"`
	PortID   int             `xml:"portid,attr"`
	State    nmapStateXML    `xml:"state"`
	Service  *nmapServiceXML `xml:"service,omitempty"`
}

type nmapStateXML struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr,omitempty"`
}

type nmapServiceXML struct {
	Name      string   `xml:"name,attr"`
	Product   string   `xml:"product,attr,omitempty"`
	Version   string   `xml:"version,attr,omitempty"`
	ExtraInfo string   `xml:"extrainfo,attr,omitempty"`
	Tunnel    string   `xml:"tunnel,attr,omitempty"`
	CPEs      []string `xml:"cpe,omitempty"`
}

type nmapOSXML struct {
	Matches []nmapOSMatchXML `xml:"osmatch"`
}

type nmapOSMatchXML struct {
	Name     string `xml:"name,attr"`
	Accuracy string `xml:"accuracy,attr"`
}

type nmapStatsXML struct {
	Finished nmapFinishedXML `xml:"finished"`
	Hosts    nmapHostCntXML  `xml:"hosts"`
}

type nmapFinishedXML struct {
	Time    int64  `xml:"time,attr"`
	TimeStr string `xml:"timestr,attr,omitempty"`
	Elapsed string `xml:"elapsed,attr,omitempty"`
}

type nmapHostCntXML struct {
	Up    int `xml:"up,attr"`
	Down  int `xml:"down,attr"`
	Total int `xml:"total,attr"`
}

// ParseNmapXML parses standard Nmap XML output into ObservedHost records.
func ParseNmapXML(xmlBytes []byte) ([]domain.ObservedHost, error) {
	if len(bytes.TrimSpace(xmlBytes)) == 0 {
		return nil, nil
	}
	var doc nmapRunXML
	if err := xml.Unmarshal(xmlBytes, &doc); err != nil {
		return nil, fmt.Errorf("parse nmap xml: %w", err)
	}

	now := time.Now().UTC()
	out := make([]domain.ObservedHost, 0, len(doc.Hosts))
	for _, h := range doc.Hosts {
		var ip string
		for _, a := range h.Addresses {
			if a.AddrType == "ipv4" || a.AddrType == "ipv6" || ip == "" {
				ip = a.Addr
				if a.AddrType == "ipv4" {
					break
				}
			}
		}
		if ip == "" {
			continue
		}

		var hostname string
		var domains []string
		for _, hn := range h.Hostnames.Hostnames {
			if hn.Name != "" {
				if hostname == "" {
					hostname = hn.Name
				}
				domains = appendUnique(domains, hn.Name)
			}
		}

		osGuess := ""
		if h.OS != nil && len(h.OS.Matches) > 0 {
			osGuess = h.OS.Matches[0].Name
		}

		var svcs []domain.ObservedService
		for _, p := range h.Ports.Ports {
			if p.State.State != "open" {
				continue
			}
			svc := domain.ObservedService{
				Port:     p.PortID,
				Protocol: p.Protocol,
				State:    p.State.State,
			}
			if p.Service != nil {
				svc.ServiceName = p.Service.Name
				if p.Service.Tunnel == "ssl" && svc.ServiceName == "http" {
					svc.ServiceName = "https"
				}
				svc.Product = p.Service.Product
				svc.Version = p.Service.Version
				svc.Banner = strings.TrimSpace(p.Service.ExtraInfo)
				if len(p.Service.CPEs) > 0 {
					svc.CPE = p.Service.CPEs[0]
				}
			}
			svcs = append(svcs, svc)
		}

		out = append(out, domain.ObservedHost{
			IP:         ip,
			Hostname:   hostname,
			Domains:    domains,
			OSGuess:    osGuess,
			IsAlive:    strings.EqualFold(h.Status.State, "up") || len(svcs) > 0,
			ObservedAt: now,
			Services:   svcs,
		})
	}
	return out, nil
}

// GenerateNmapXML builds a DefectDojo-compatible Nmap XML document from ObservedHost records.
func GenerateNmapXML(hosts []domain.ObservedHost, args string, startedAt, finishedAt time.Time) string {
	if startedAt.IsZero() {
		startedAt = time.Now().UTC()
	}
	if finishedAt.IsZero() {
		finishedAt = time.Now().UTC()
	}
	if args == "" {
		args = "nmap -sT -sV"
	}

	doc := nmapRunXML{
		Scanner:   "nmap",
		Args:      args,
		Start:     startedAt.Unix(),
		StartStr:  startedAt.Format(time.RFC1123),
		Version:   "7.94",
		XMLOutVer: "1.05",
	}

	upCount := 0
	for _, h := range hosts {
		state := "down"
		if h.IsAlive {
			state = "up"
			upCount++
		}
		addrType := "ipv4"
		if strings.Contains(h.IP, ":") {
			addrType = "ipv6"
		}
		nh := nmapHostXML{
			Status: nmapStatusXML{State: state, Reason: "syn-ack"},
			Addresses: []nmapAddrXML{
				{Addr: h.IP, AddrType: addrType},
			},
		}
		if h.Hostname != "" {
			nh.Hostnames.Hostnames = append(nh.Hostnames.Hostnames, nmapHostnameXML{Name: h.Hostname, Type: "user"})
		}
		for _, s := range h.Services {
			proto := s.Protocol
			if proto == "" {
				proto = "tcp"
			}
			np := nmapPortXML{
				Protocol: proto,
				PortID:   s.Port,
				State:    nmapStateXML{State: s.State, Reason: "syn-ack"},
				Service: &nmapServiceXML{
					Name:      s.ServiceName,
					Product:   s.Product,
					Version:   s.Version,
					ExtraInfo: s.Banner,
				},
			}
			if s.CPE != "" {
				np.Service.CPEs = []string{s.CPE}
			}
			nh.Ports.Ports = append(nh.Ports.Ports, np)
		}
		doc.Hosts = append(doc.Hosts, nh)
	}

	elapsed := finishedAt.Sub(startedAt).Seconds()
	if elapsed < 0 {
		elapsed = 0
	}
	doc.RunStats = &nmapStatsXML{
		Finished: nmapFinishedXML{
			Time:    finishedAt.Unix(),
			TimeStr: finishedAt.Format(time.RFC1123),
			Elapsed: fmt.Sprintf("%.2f", elapsed),
		},
		Hosts: nmapHostCntXML{
			Up:    upCount,
			Down:  len(hosts) - upCount,
			Total: len(hosts),
		},
	}

	raw, err := xml.MarshalIndent(doc, "", "  ")
	if err != nil {
		return ""
	}
	return xml.Header + string(raw)
}

// MergeNmapXML combines multiple per-chunk Nmap XML documents into a single valid
// Nmap XML document suitable for DefectDojo /api/v2/import-scan/ (scan_type="Nmap Scan").
func MergeNmapXML(xmlDocs []string) string {
	var merged nmapRunXML
	merged.Scanner = "nmap"
	merged.Version = "7.94"
	merged.XMLOutVer = "1.05"
	merged.Args = "nmap -sT -sV (aggregated chunks)"

	seenHostIdx := make(map[string]int)
	var minStart int64
	var maxEnd int64

	for _, docStr := range xmlDocs {
		if strings.TrimSpace(docStr) == "" {
			continue
		}
		var doc nmapRunXML
		if err := xml.Unmarshal([]byte(docStr), &doc); err != nil {
			continue
		}
		if doc.Start > 0 && (minStart == 0 || doc.Start < minStart) {
			minStart = doc.Start
			merged.StartStr = doc.StartStr
		}
		if doc.RunStats != nil && doc.RunStats.Finished.Time > maxEnd {
			maxEnd = doc.RunStats.Finished.Time
		}
		for _, h := range doc.Hosts {
			var ip string
			for _, a := range h.Addresses {
				if a.Addr != "" {
					ip = a.Addr
					break
				}
			}
			if ip == "" {
				continue
			}
			if idx, exists := seenHostIdx[ip]; exists {
				// Replace if new entry has more ports.
				if len(h.Ports.Ports) > len(merged.Hosts[idx].Ports.Ports) {
					merged.Hosts[idx] = h
				}
			} else {
				seenHostIdx[ip] = len(merged.Hosts)
				merged.Hosts = append(merged.Hosts, h)
			}
		}
	}

	if len(merged.Hosts) == 0 {
		return ""
	}

	now := time.Now().UTC()
	if minStart == 0 {
		minStart = now.Unix()
	}
	if maxEnd == 0 {
		maxEnd = now.Unix()
	}
	merged.Start = minStart
	up := 0
	for _, h := range merged.Hosts {
		if strings.EqualFold(h.Status.State, "up") {
			up++
		}
	}
	merged.RunStats = &nmapStatsXML{
		Finished: nmapFinishedXML{
			Time:    maxEnd,
			TimeStr: time.Unix(maxEnd, 0).UTC().Format(time.RFC1123),
			Elapsed: fmt.Sprintf("%.2f", float64(maxEnd-minStart)),
		},
		Hosts: nmapHostCntXML{
			Up:    up,
			Down:  len(merged.Hosts) - up,
			Total: len(merged.Hosts),
		},
	}

	raw, err := xml.MarshalIndent(merged, "", "  ")
	if err != nil {
		return ""
	}
	return xml.Header + string(raw)
}
