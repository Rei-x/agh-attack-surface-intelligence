package auth

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

type ctxKey struct{}

// SSEPath is the only endpoint that accepts the token as a ?token= query parameter.
const SSEPath = "/api/v1/events/stream"

// UserLoader resolves a user by ID with current role permissions from persistence.
type UserLoader interface {
	GetUser(ctx context.Context, id string) (*domain.User, error)
}

// AuditLogger persists audit entries for access control decisions.
type AuditLogger interface {
	AddAuditLog(ctx context.Context, entry *domain.AuditLog) error
}

// Middleware authenticates JWT tokens and enforces dynamic RBAC permissions.
type Middleware struct {
	secret []byte
	users  UserLoader
	audit  AuditLogger
	// IsNotFound classifies UserLoader errors. When set, any other error (database down) is
	// answered with 503 instead of 401, so an outage does not log every user out.
	IsNotFound func(error) bool
}

// NewMiddleware returns the JWT authentication middleware.
func NewMiddleware(secret []byte, users UserLoader, audit AuditLogger) *Middleware {
	return &Middleware{
		secret: secret,
		users:  users,
		audit:  audit,
	}
}

// UserFromContext returns the authenticated user attached to ctx, or nil.
func UserFromContext(ctx context.Context) *domain.User {
	u, _ := ctx.Value(ctxKey{}).(*domain.User)
	return u
}

// Authenticate validates Bearer JWT (or ?token= for SSE) and loads live user permissions.
func (m *Middleware) Authenticate(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := extractToken(r)
		if token == "" {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized", "missing bearer token")
			return
		}
		claims, err := VerifyToken(m.secret, token)
		if err != nil {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized", err.Error())
			return
		}
		user, err := m.users.GetUser(r.Context(), claims.Sub)
		if err != nil && m.IsNotFound != nil && !m.IsNotFound(err) {
			writeJSONError(w, http.StatusServiceUnavailable, "baza danych jest niedostępna - spróbuj ponownie za chwilę / database unavailable",
				"store error while loading the user")
			return
		}
		if err != nil || user == nil || !user.Active {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized", "account inactive or not found")
			return
		}
		ctx := context.WithValue(r.Context(), ctxKey{}, user)
		next(w, r.WithContext(ctx))
	}
}

// RequirePerm authenticates the request and strictly enforces that the user holds perm.
// Unauthorized actions return 403 Forbidden and are recorded in audit_logs.
func (m *Middleware) RequirePerm(perm string, next http.HandlerFunc) http.HandlerFunc {
	return m.Authenticate(func(w http.ResponseWriter, r *http.Request) {
		user := UserFromContext(r.Context())
		if user == nil {
			writeJSONError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
			return
		}
		if !HasPermission(user.Permissions, perm) {
			m.recordAudit(r, user, "denied", perm)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":               "forbidden",
				"message":             "insufficient permissions",
				"required_permission": perm,
				"role":                user.RoleSlug,
			})
			return
		}

		// Record mutating requests as audit entries.
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
			m.recordAudit(r, user, "success", perm)
		}
		next(w, r)
	})
}

func (m *Middleware) recordAudit(r *http.Request, user *domain.User, status, perm string) {
	if m.audit == nil {
		return
	}
	ip := clientIP(r)
	_ = m.audit.AddAuditLog(r.Context(), &domain.AuditLog{
		UserID:    user.ID,
		Username:  user.Username,
		RoleSlug:  user.RoleSlug,
		Action:    r.Method + " " + r.URL.Path,
		Resource:  perm,
		Status:    status,
		IPAddress: ip,
		Details: map[string]any{
			"required_permission": perm,
			"method":              r.Method,
			"path":                r.URL.Path,
		},
		CreatedAt: time.Now().UTC(),
	})
}

func extractToken(r *http.Request) string {
	authz := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(authz) > 7 && strings.EqualFold(authz[:7], "Bearer ") {
		return strings.TrimSpace(authz[7:])
	}
	// EventSource cannot send headers, so the SSE stream (only) accepts ?token=. Elsewhere a
	// token in the URL would leak into proxy logs, browser history and Referer headers.
	if r.URL.Path == SSEPath {
		if q := strings.TrimSpace(r.URL.Query().Get("token")); q != "" {
			return q
		}
	}
	return ""
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeJSONError(w http.ResponseWriter, code int, errCode, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":   errCode,
		"message": msg,
	})
}
