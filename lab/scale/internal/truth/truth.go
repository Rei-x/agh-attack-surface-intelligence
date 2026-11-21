// Package truth defines the ground-truth document emitted by the scale lab
// (GET /truth, /truth/<scenario>.json) and consumed by the scorer.
package truth

import "time"

// Document is the ground truth for one scenario at one point in time.
type Document struct {
	Scenario    string    `json:"scenario"`
	CIDR        string    `json:"cidr"`
	Seed        uint64    `json:"seed"`
	GeneratedAt time.Time `json:"generated_at"`
	// MarkedAt is when the current observation window started (POST /mark).
	// Hosts whose up/down state changed since then carry Toggled=true.
	MarkedAt *time.Time `json:"marked_at,omitempty"`
	// Ports is the sorted union of every TCP port any lab host may expose.
	Ports []int  `json:"ports"`
	Hosts []Host `json:"hosts"`
}

// Host is one IP that exists in the lab in some scenario.
// Hosts that are not alive in this scenario are still listed (Alive=false)
// when they are alive in another scenario, so diffs are computable.
type Host struct {
	IP        string `json:"ip"`
	Alive     bool   `json:"alive"`
	Hostname  string `json:"hostname,omitempty"`
	Archetype string `json:"archetype"`
	// ICMPBlocked: host drops all ICMP (only TCP-discoverable).
	ICMPBlocked bool `json:"icmp_blocked,omitempty"`
	// Firewalled: closed ports are silently DROPped instead of RST.
	Firewalled bool `json:"firewalled,omitempty"`
	// Flapping hosts toggle up/down with FlapPeriodSec; always scored leniently.
	Flapping      bool `json:"flapping,omitempty"`
	FlapPeriodSec int  `json:"flap_period_sec,omitempty"`
	// TimeOfDay hosts are only up between StartHour and EndHour (lab TZ).
	TimeOfDay *HourRange `json:"time_of_day,omitempty"`
	// Toggled is true when the host's state changed since the last /mark.
	Toggled  bool      `json:"toggled,omitempty"`
	Services []Service `json:"services,omitempty"`
}

// HourRange is [Start, End) in local hours; Start > End wraps midnight.
type HourRange struct {
	Start int    `json:"start"`
	End   int    `json:"end"`
	TZ    string `json:"tz"`
}

// Service is one open TCP port with its expected identification.
type Service struct {
	Port  int    `json:"port"`
	Proto string `json:"proto"`
	// Service is the nmap-style service name (ssh, http, https, ftp, smtp, mysql ...).
	Service string `json:"service"`
	// Product / Version as a real server of that kind would disclose them on the wire.
	// Empty when the product does not disclose a version.
	Product string `json:"product,omitempty"`
	Version string `json:"version,omitempty"`
	TLS     bool   `json:"tls,omitempty"`
	// Banner is the first line a server-first protocol sends (ssh/ftp/smtp...).
	Banner string `json:"banner,omitempty"`
	// Technologies are canonical lowercase tech identifiers (wordpress, nginx, php ...).
	Technologies []string `json:"technologies,omitempty"`
	Flags        Flags    `json:"flags"`
	HTTP         *HTTP    `json:"http,omitempty"`
}

// Flags are the classification labels we expect a good scanner to assign.
type Flags struct {
	AdminPanel bool `json:"admin_panel"`
	Staging    bool `json:"staging"`
	IoT        bool `json:"iot"`
}

// HTTP describes what a browser-like GET / (following same-host redirects) sees.
type HTTP struct {
	App         string   `json:"app"`
	FinalPath   string   `json:"final_path"`
	Status      int      `json:"status"`
	Title       string   `json:"title,omitempty"`
	Server      string   `json:"server,omitempty"`
	Redirects   []string `json:"redirects,omitempty"`
	MetaGen     string   `json:"meta_generator,omitempty"`
	TechVersion string   `json:"tech_version,omitempty"`
	// InterestingHeaders: lowercase names of technology/version disclosing headers.
	InterestingHeaders []string `json:"interesting_headers,omitempty"`
	MissingSecHeaders  []string `json:"missing_sec_headers,omitempty"`
	Cookies            []Cookie `json:"cookies,omitempty"`
	// InsecureCookies: names of cookies set without Secure or without HttpOnly.
	InsecureCookies []string `json:"insecure_cookies,omitempty"`
	CertKind        string   `json:"cert_kind,omitempty"` // valid|self_signed|expired
	CertCN          string   `json:"cert_cn,omitempty"`
}

// Cookie as set by the server on the observed page(s).
type Cookie struct {
	Name     string `json:"name"`
	Secure   bool   `json:"secure"`
	HttpOnly bool   `json:"http_only"`
	Path     string `json:"path,omitempty"`
}

// AliveHosts returns a map ip -> host for alive hosts only.
func (d *Document) AliveHosts() map[string]*Host {
	out := make(map[string]*Host)
	for i := range d.Hosts {
		if d.Hosts[i].Alive {
			out[d.Hosts[i].IP] = &d.Hosts[i]
		}
	}
	return out
}

// Unstable reports whether the host must be scored leniently.
func (h *Host) Unstable() bool { return h.Flapping || h.Toggled }
