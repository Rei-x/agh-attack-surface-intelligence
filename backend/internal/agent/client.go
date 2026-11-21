package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/agenthub"
)

// apiError is a non-2xx answer from the server.
type apiError struct {
	Status int
	Msg    string
}

func (e *apiError) Error() string { return fmt.Sprintf("server answered %d: %s", e.Status, e.Msg) }

// retryable reports errors worth retrying later: network failures, timeouts, 5xx, 429.
func retryable(err error) bool {
	var ae *apiError
	if errors.As(err, &ae) {
		return ae.Status >= 500 || ae.Status == http.StatusTooManyRequests || ae.Status == http.StatusRequestTimeout
	}
	return err != nil
}

func statusOf(err error) int {
	var ae *apiError
	if errors.As(err, &ae) {
		return ae.Status
	}
	return 0
}

// client talks to the AegisASI server over HTTPS (outbound only).
type client struct {
	base       *url.URL
	http       *http.Client
	credential string
	instance   string
	userAgent  string
}

// checkServerURL enforces transport security: HTTPS, or plain HTTP only to this machine or
// with --insecure (lab use).
func checkServerURL(raw string, insecure bool) (*url.URL, error) {
	u, err := url.Parse(strings.TrimRight(strings.TrimSpace(raw), "/"))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("invalid --server %q (want https://host[:port])", raw)
	}
	if u.Scheme == "http" && !insecure {
		host := u.Hostname()
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return nil, fmt.Errorf("refusing plain HTTP to %s: the agent credential would travel unencrypted - use https:// (or --insecure in a lab)", host)
		}
	}
	return u, nil
}

func newHTTPClient(caFile string, insecure bool) (*http.Client, error) {
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read --ca-file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("--ca-file %s contains no PEM certificate", caFile)
		}
		tlsCfg.RootCAs = pool
	}
	if insecure {
		tlsCfg.InsecureSkipVerify = true // explicit lab opt-in (--insecure), warned about at startup
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsCfg
	tr.Proxy = http.ProxyFromEnvironment // HTTPS_PROXY for segments that only reach out via a proxy
	tr.ResponseHeaderTimeout = 0         // long-poll; per-request contexts bound every call
	return &http.Client{Transport: tr}, nil
}

// do sends one JSON request. out may be nil. A 204 leaves out untouched and returns (204, nil).
func (c *client) do(ctx context.Context, timeout time.Duration, method, path string, in, out any) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return 0, err
		}
		body = bytes.NewReader(raw)
	}
	u := *c.base
	p, q, _ := strings.Cut(path, "?")
	u.Path = strings.TrimRight(u.Path, "/") + p
	u.RawQuery = q
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	if c.credential != "" {
		req.Header.Set("Authorization", "Bearer "+c.credential)
	}
	if c.instance != "" {
		req.Header.Set(agenthub.InstanceHeader, c.instance)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<20))
	if resp.StatusCode == http.StatusNoContent {
		return resp.StatusCode, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(raw, &e)
		if e.Error == "" {
			e.Error = strings.TrimSpace(string(raw))
			if len(e.Error) > 200 {
				e.Error = e.Error[:200]
			}
		}
		return resp.StatusCode, &apiError{Status: resp.StatusCode, Msg: e.Error}
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, fmt.Errorf("decode %s response: %w", path, err)
		}
	}
	return resp.StatusCode, nil
}
