package api

import (
	"errors"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/eol"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/screenshot"
)

// Web screenshot gallery (internal/screenshot). Images are served only to authenticated
// users with assets:read; there are no public or signed URLs. The UI fetches them with its
// bearer token and shows blob: URLs.

// SetScreenshots attaches the encrypted screenshot store (nil: gallery reports it is off).
func (s *Server) SetScreenshots(st *screenshot.Store) {
	if st == nil {
		return
	}
	s.shots = st
}

func (s *Server) registerScreenshotRoutes() {
	mw := s.authMW
	s.handle("GET /api/v1/screenshots", mw.RequirePerm(domain.PermAssetsRead, s.handleListScreenshots))
	s.handle("GET /api/v1/screenshots/{id}", mw.RequirePerm(domain.PermAssetsRead, s.handleScreenshotImage))
	s.handle("GET /api/v1/hosts/{id}/screenshots", mw.RequirePerm(domain.PermAssetsRead, s.handleHostScreenshots))
}

// GalleryItem is one tile of the gallery: the newest screenshot of a service plus enough of
// the host and service to label it (logo, categories, title).
type GalleryItem struct {
	HostID   string           `json:"host_id"`
	HostIP   string           `json:"host_ip"`
	Hostname string           `json:"hostname,omitempty"`
	Owner    string           `json:"owner,omitempty"`
	Service  domain.Service   `json:"service"`
	Shot     screenshot.Entry `json:"shot"`
	Versions int              `json:"versions"` // stored screenshots of this service
	Key      screenshot.Key   `json:"key"`
	Kinds    []string         `json:"kinds,omitempty"`
}

// defaultPageRE matches out-of-the-box server pages ("Apache2 Ubuntu Default Page",
// "Welcome to nginx!", "IIS Windows Server", "Apache Tomcat/9.0.x", "It works!").
var defaultPageRE = regexp.MustCompile(`(?i)(default|test|placeholder) page|^it works|welcome to (nginx|centos|openresty|caddy|tengine)|iis windows server|^iis\d|apache tomcat/|^welcome to jboss|^welcome to wildfly|congratulations|^index of /$`)

// galleryKinds are the filter chips of the gallery.
var galleryKinds = []string{"admin", "iot", "default", "eol"}

func galleryKindsOf(svc *domain.Service, title string) []string {
	var out []string
	if svc.IsAdminPanel {
		out = append(out, "admin")
	}
	bmc := false
	for _, t := range svc.Technologies {
		n := strings.ToLower(t.Name)
		if strings.Contains(n, "bmc") || strings.Contains(n, "idrac") || strings.Contains(n, "lights-out") || strings.Contains(n, "ipmi") {
			bmc = true
			break
		}
	}
	if svc.IsIoT || bmc {
		out = append(out, "iot")
	}
	httpTitle := ""
	if svc.HTTP != nil {
		httpTitle = svc.HTTP.Title
	}
	if defaultPageRE.MatchString(strings.TrimSpace(httpTitle)) || defaultPageRE.MatchString(strings.TrimSpace(title)) {
		out = append(out, "default")
	}
	if len(svc.Outdated) > 0 {
		out = append(out, "eol")
	}
	return out
}

// publicScreenshotStatus is the unauthenticated /health view: no browser path.
func publicScreenshotStatus() string {
	a := screenshot.Status()
	if a.Available {
		return "on"
	}
	return a.Detail
}

func (s *Server) screenshotStatus() map[string]any {
	a := screenshot.Status()
	out := map[string]any{"available": a.Available, "detail": a.Detail, "store": s.shots != nil}
	if s.shots == nil {
		out["detail"] = "screenshot store is off (no data directory)"
	}
	return out
}

func (s *Server) handleListScreenshots(w http.ResponseWriter, r *http.Request) {
	qv := r.URL.Query()
	limit := queryInt(r, "limit", 60)
	if limit <= 0 || limit > 500 {
		limit = 60
	}
	page := queryInt(r, "page", 1)
	if page < 1 {
		page = 1
	}
	query, err := db.ParseAssetQuery(qv.Get("q"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "query: "+err.Error())
		return
	}
	kind := strings.ToLower(strings.TrimSpace(qv.Get("kind")))
	if kind != "" && !shotContains(galleryKinds, kind) {
		writeErr(w, http.StatusBadRequest, "kind must be one of "+strings.Join(galleryKinds, ", "))
		return
	}
	resp := map[string]any{
		"items": []GalleryItem{}, "total": 0, "page": page, "limit": limit, "total_pages": 1,
		"counts": map[string]int{}, "status": s.screenshotStatus(),
	}
	if s.shots == nil {
		writeJSON(w, http.StatusOK, resp)
		return
	}
	items, err := s.galleryItems(r, query)
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	counts := map[string]int{"all": len(items)}
	filtered := items[:0:0]
	for _, it := range items {
		for _, k := range it.Kinds {
			counts[k]++
		}
		if kind == "" || shotContains(it.Kinds, kind) {
			filtered = append(filtered, it)
		}
	}
	sort.SliceStable(filtered, func(i, j int) bool {
		a, b := filtered[i], filtered[j]
		if a.Service.Interestingness != b.Service.Interestingness {
			return a.Service.Interestingness > b.Service.Interestingness
		}
		if a.HostIP != b.HostIP {
			return shotIPLess(a.HostIP, b.HostIP)
		}
		return a.Key.Port < b.Key.Port
	})
	total := len(filtered)
	start := (page - 1) * limit
	if start > total {
		start = total
	}
	end := start + limit
	if end > total {
		end = total
	}
	resp["items"] = filtered[start:end]
	resp["total"] = total
	resp["counts"] = counts
	resp["total_pages"] = max(1, (total+limit-1)/limit)
	writeJSON(w, http.StatusOK, resp)
}

// galleryItems joins the newest screenshot of every service with the asset store and keeps
// those matching the asset query (host terms on the host, service terms on that service).
func (s *Server) galleryItems(r *http.Request, query *db.AssetQuery) ([]GalleryItem, error) {
	ctx := r.Context()
	svcQuery := query.ServiceOnly()
	now := time.Now().UTC()
	hosts := map[string]*domain.Host{}
	var out []GalleryItem
	for _, svc := range s.shots.Latest() {
		ip := svc.Key.IP
		h, seen := hosts[ip]
		if !seen {
			got, err := s.store.GetHostByIP(ctx, ip)
			if err != nil && !errors.Is(err, db.ErrNotFound) {
				return nil, err
			}
			if got != nil {
				eol.AnnotateServices(got.Services, now)
			}
			hosts[ip], h = got, got
		}
		if h == nil {
			continue // host deleted from the inventory
		}
		var match *domain.Service
		for i := range h.Services {
			p := h.Services[i].Protocol
			if h.Services[i].Port == svc.Key.Port && (p == "" || strings.EqualFold(p, svc.Key.Protocol)) {
				match = &h.Services[i]
				break
			}
		}
		if match == nil {
			continue
		}
		if len(query.Terms) > 0 || len(query.Text) > 0 {
			if !query.MatchHost(h) {
				continue
			}
			if svcQuery != nil && !svcQuery.MatchService(match) {
				continue
			}
		}
		shot := svc.Entries[0]
		item := GalleryItem{
			HostID: h.ID, HostIP: h.IP, Hostname: h.Hostname, Owner: h.Owner,
			Service: *match, Shot: shot, Key: svc.Key,
			Versions: len(s.shots.History(svc.Key)),
			Kinds:    galleryKindsOf(match, shot.Title),
		}
		item.Service.HostIP = h.IP
		out = append(out, item)
	}
	return out, nil
}

func (s *Server) handleScreenshotImage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.shots == nil || !s.shots.Owns(id) {
		writeErr(w, http.StatusNotFound, "screenshot not found")
		return
	}
	img, err := s.shots.Read(id)
	if err != nil {
		if errors.Is(err, screenshot.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "screenshot not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, "could not read screenshot")
		return
	}
	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Content-Length", strconv.Itoa(len(img)))
	w.Header().Set("Cache-Control", "private, no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(img)
}

func (s *Server) handleHostScreenshots(w http.ResponseWriter, r *http.Request) {
	h, err := s.store.GetHost(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	services := []screenshot.Service{}
	if s.shots != nil {
		if got := s.shots.ForIP(h.IP); got != nil {
			services = got
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"host_id": h.ID, "services": services, "status": s.screenshotStatus()})
}

func shotContains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// ipLess orders dotted IPv4 addresses numerically (falls back to string order).
func shotIPLess(a, b string) bool {
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	if len(pa) == 4 && len(pb) == 4 {
		for i := 0; i < 4; i++ {
			x, ex := strconv.Atoi(pa[i])
			y, ey := strconv.Atoi(pb[i])
			if ex != nil || ey != nil {
				break
			}
			if x != y {
				return x < y
			}
		}
	}
	return a < b
}
