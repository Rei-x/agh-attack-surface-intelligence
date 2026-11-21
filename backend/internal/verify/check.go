// Package verify runs safe verification checks ("Verify" deep mode) that turn a possible
// exposure into a confirmed one, with evidence.
//
// Checks are small declarative YAML files (checks/*.yaml, embedded) in a subset of the
// Nuclei template syntax, so a pentester can read and extend them:
//
//	id: redis-unauth
//	info: {name: ..., severity: high, description: ..., remediation: ..., reference: [...]}
//	match: {ports: [6379], services: [redis]}        # Dzięcioł: which services it applies to
//	network:                                          # Nuclei "network" (tcp) request
//	  - inputs: [{data: "INFO server\r\n"}]
//	    read-size: 2048
//	    matchers: [{type: word, words: ["redis_version:"]}]
//	http:                                             # Nuclei "http" request
//	  - method: GET
//	    path: ["{{BaseURL}}/.git/HEAD"]
//	    matchers-condition: and
//	    matchers: [{type: status, status: [200]}, {type: regex, part: body, regex: ["^ref: refs/"]}]
//
// Supported: http (GET/HEAD/POST/OPTIONS, path list, headers, body, matchers word / regex /
// status with part, condition, negative, case-insensitive; regex extractors), network
// (text or hex inputs, per-input read, read-size) and two built-in TLS probes. Not supported
// on purpose: raw requests, payloads/fuzzing, DSL, workflows, OOB interactions.
//
// Safety rules enforced by the engine, not by the check author: only read-only HTTP methods,
// small bounded responses, one request at a time per host through the scan governor, only
// hosts inside the profile's targets, and checks marked `requires: default-creds` only when
// the profile explicitly enables "check default credentials" (each attempt is audited).
package verify

import (
	"embed"
	"encoding/hex"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed checks/*.yaml
var checksFS embed.FS

// StringList accepts a YAML scalar or a sequence (Nuclei allows both for reference/tags).
type StringList []string

// UnmarshalYAML implements yaml.Unmarshaler.
func (s *StringList) UnmarshalYAML(n *yaml.Node) error {
	switch n.Kind {
	case yaml.ScalarNode:
		var v string
		if err := n.Decode(&v); err != nil {
			return err
		}
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				*s = append(*s, p)
			}
		}
		return nil
	case yaml.SequenceNode:
		var v []string
		if err := n.Decode(&v); err != nil {
			return err
		}
		*s = v
		return nil
	}
	return fmt.Errorf("line %d: expected a string or a list", n.Line)
}

// Info is the Nuclei-compatible metadata block.
type Info struct {
	Name        string     `yaml:"name" json:"name"`
	Author      StringList `yaml:"author" json:"author,omitempty"`
	Severity    string     `yaml:"severity" json:"severity"`
	Description string     `yaml:"description" json:"description"`
	Remediation string     `yaml:"remediation" json:"remediation"`
	Reference   StringList `yaml:"reference" json:"reference,omitempty"`
	Tags        StringList `yaml:"tags" json:"tags,omitempty"`
}

// Applies selects the services a check runs against (Dzięcioł extension). A service
// qualifies when any listed port, service name, product or technology matches; AnyHTTP
// makes an http check apply to every web service.
type Applies struct {
	Ports    []int      `yaml:"ports" json:"ports,omitempty"`
	Services StringList `yaml:"services" json:"services,omitempty"`
	Products StringList `yaml:"products" json:"products,omitempty"`
	Techs    StringList `yaml:"techs" json:"techs,omitempty"`
	AnyHTTP  bool       `yaml:"any-http" json:"any_http,omitempty"`
}

// Matcher is a Nuclei matcher (word, regex, status).
type Matcher struct {
	Type            string   `yaml:"type"`
	Part            string   `yaml:"part"` // body (default), header, all, raw
	Words           []string `yaml:"words"`
	Regex           []string `yaml:"regex"`
	Status          []int    `yaml:"status"`
	Condition       string   `yaml:"condition"` // or (default), and
	Negative        bool     `yaml:"negative"`
	CaseInsensitive bool     `yaml:"case-insensitive"`

	res []*regexp.Regexp
}

// Extractor pulls a value into the evidence (Nuclei regex extractor).
type Extractor struct {
	Type  string   `yaml:"type"`
	Name  string   `yaml:"name"`
	Part  string   `yaml:"part"`
	Regex []string `yaml:"regex"`
	Group int      `yaml:"group"`

	res []*regexp.Regexp
}

// HTTPRequest is one Nuclei http block.
type HTTPRequest struct {
	Method            string            `yaml:"method"`
	Path              []string          `yaml:"path"`
	Headers           map[string]string `yaml:"headers"`
	Body              string            `yaml:"body"`
	MatchersCondition string            `yaml:"matchers-condition"`
	Matchers          []Matcher         `yaml:"matchers"`
	Extractors        []Extractor       `yaml:"extractors"`
	MaxSize           int               `yaml:"max-size"`
	// BasicAuth (Dzięcioł extension, default-credential checks only): "user:password".
	BasicAuth string `yaml:"basic-auth"`
}

// NetInput is one Nuclei network input.
type NetInput struct {
	Data string `yaml:"data"`
	Type string `yaml:"type"` // text (default) or hex
	Read int    `yaml:"read"` // bytes to read after sending

	raw []byte
}

// NetRequest is one Nuclei network block.
type NetRequest struct {
	Inputs            []NetInput  `yaml:"inputs"`
	ReadSize          int         `yaml:"read-size"`
	MatchersCondition string      `yaml:"matchers-condition"`
	Matchers          []Matcher   `yaml:"matchers"`
	Extractors        []Extractor `yaml:"extractors"`
	// TLS wraps the connection (Dzięcioł extension).
	TLS bool `yaml:"tls"`
}

// Check is one verification check.
type Check struct {
	ID       string        `yaml:"id" json:"id"`
	Info     Info          `yaml:"info" json:"info"`
	Match    Applies       `yaml:"match" json:"match"`
	Requires string        `yaml:"requires" json:"requires,omitempty"` // "default-creds"
	Builtin  string        `yaml:"builtin" json:"builtin,omitempty"`   // tls-protocols, tls-certificate
	HTTP     []HTTPRequest `yaml:"http" json:"-"`
	Requests []HTTPRequest `yaml:"requests" json:"-"` // legacy Nuclei name of http
	Network  []NetRequest  `yaml:"network" json:"-"`
	TCP      []NetRequest  `yaml:"tcp" json:"-"` // legacy Nuclei name of network
	Source   string        `yaml:"-" json:"source"`
}

// Kind reports http, network or builtin.
func (c *Check) Kind() string {
	switch {
	case c.Builtin != "":
		return "builtin"
	case len(c.Network) > 0:
		return "network"
	}
	return "http"
}

// DefaultCreds reports whether the check tries a default credential.
func (c *Check) DefaultCreds() bool { return c.Requires == RequiresDefaultCreds }

// RequiresDefaultCreds marks checks gated by the profile's "check default credentials".
const RequiresDefaultCreds = "default-creds"

var safeMethods = map[string]bool{"GET": true, "HEAD": true, "POST": true, "OPTIONS": true}

var builtins = map[string]bool{"tls-protocols": true, "tls-certificate": true}

var severities = map[string]bool{"info": true, "low": true, "medium": true, "high": true, "critical": true}

// ParseCheck decodes and validates one check.
func ParseCheck(raw []byte, source string) (*Check, error) {
	var c Check
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	c.Source = source
	c.HTTP = append(c.HTTP, c.Requests...)
	c.Requests = nil
	c.Network = append(c.Network, c.TCP...)
	c.TCP = nil
	if err := c.compile(); err != nil {
		return nil, fmt.Errorf("%s: %w", source, err)
	}
	return &c, nil
}

func (c *Check) compile() error {
	if c.ID == "" || c.Info.Name == "" {
		return fmt.Errorf("id and info.name are required")
	}
	c.Info.Severity = strings.ToLower(strings.TrimSpace(c.Info.Severity))
	if !severities[c.Info.Severity] {
		return fmt.Errorf("%s: unknown severity %q", c.ID, c.Info.Severity)
	}
	if c.Requires != "" && c.Requires != RequiresDefaultCreds {
		return fmt.Errorf("%s: unknown requires %q", c.ID, c.Requires)
	}
	n := 0
	if c.Builtin != "" {
		if !builtins[c.Builtin] {
			return fmt.Errorf("%s: unknown builtin %q", c.ID, c.Builtin)
		}
		n++
	}
	if len(c.HTTP) > 0 {
		n++
	}
	if len(c.Network) > 0 {
		n++
	}
	if n != 1 {
		return fmt.Errorf("%s: exactly one of http, network or builtin is required", c.ID)
	}
	for i := range c.HTTP {
		r := &c.HTTP[i]
		r.Method = strings.ToUpper(strings.TrimSpace(r.Method))
		if r.Method == "" {
			r.Method = "GET"
		}
		if !safeMethods[r.Method] {
			return fmt.Errorf("%s: method %s is not allowed (read-only checks only)", c.ID, r.Method)
		}
		if len(r.Path) == 0 {
			return fmt.Errorf("%s: http request without path", c.ID)
		}
		if r.BasicAuth != "" && !c.DefaultCreds() {
			return fmt.Errorf("%s: basic-auth requires `requires: default-creds`", c.ID)
		}
		if err := compileMatchers(r.Matchers, r.Extractors); err != nil {
			return fmt.Errorf("%s: %w", c.ID, err)
		}
	}
	for i := range c.Network {
		r := &c.Network[i]
		for j := range r.Inputs {
			in := &r.Inputs[j]
			switch strings.ToLower(in.Type) {
			case "", "text":
				in.raw = []byte(in.Data)
			case "hex":
				b, err := hex.DecodeString(strings.ReplaceAll(in.Data, " ", ""))
				if err != nil {
					return fmt.Errorf("%s: bad hex input: %w", c.ID, err)
				}
				in.raw = b
			default:
				return fmt.Errorf("%s: unknown input type %q", c.ID, in.Type)
			}
		}
		if err := compileMatchers(r.Matchers, r.Extractors); err != nil {
			return fmt.Errorf("%s: %w", c.ID, err)
		}
	}
	return nil
}

func compileMatchers(ms []Matcher, xs []Extractor) error {
	if len(ms) == 0 {
		return fmt.Errorf("at least one matcher is required")
	}
	for i := range ms {
		m := &ms[i]
		switch m.Type {
		case "word":
			if len(m.Words) == 0 {
				return fmt.Errorf("word matcher without words")
			}
		case "regex":
			for _, r := range m.Regex {
				if m.CaseInsensitive && !strings.HasPrefix(r, "(?i)") {
					r = "(?i)" + r
				}
				re, err := regexp.Compile(r)
				if err != nil {
					return fmt.Errorf("regex %q: %w", r, err)
				}
				m.res = append(m.res, re)
			}
			if len(m.res) == 0 {
				return fmt.Errorf("regex matcher without regex")
			}
		case "status":
			if len(m.Status) == 0 {
				return fmt.Errorf("status matcher without status")
			}
		default:
			return fmt.Errorf("unsupported matcher type %q (word, regex, status)", m.Type)
		}
	}
	for i := range xs {
		x := &xs[i]
		if x.Type != "regex" {
			return fmt.Errorf("unsupported extractor type %q (regex)", x.Type)
		}
		for _, r := range x.Regex {
			re, err := regexp.Compile(r)
			if err != nil {
				return fmt.Errorf("extractor regex %q: %w", r, err)
			}
			x.res = append(x.res, re)
		}
	}
	return nil
}

// LoadBuiltinChecks parses the embedded checks, sorted by id.
func LoadBuiltinChecks() ([]*Check, error) {
	var out []*Check
	err := fs.WalkDir(checksFS, "checks", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".yaml") {
			return err
		}
		raw, err := checksFS.ReadFile(path)
		if err != nil {
			return err
		}
		c, err := ParseCheck(raw, path)
		if err != nil {
			return err
		}
		out = append(out, c)
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, err
}

// ReadCheckSource returns the YAML text of an embedded check (shown in the UI).
func ReadCheckSource(source string) (string, error) {
	raw, err := checksFS.ReadFile(source)
	return string(raw), err
}
