package agenthub

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

// EnrollPattern is the only agent route reachable without an agent credential (the one-time
// token in the body authenticates it).
const EnrollPattern = "POST /api/v1/agent/enroll"

// PathPrefix is the URL prefix of every agent-protocol route.
const PathPrefix = "/api/v1/agent/"

// Route is one agent-protocol endpoint.
type Route struct {
	Pattern string
	Handler http.HandlerFunc
}

type agentCtxKey struct{}

type agentIdentity struct {
	agent    *domain.Agent
	instance string
}

// Routes returns the agent-protocol endpoints. Every route except enroll requires an agent
// credential; user JWTs are rejected (and agent credentials are rejected by user routes,
// because they are not JWTs).
func (c *Coordinator) Routes() []Route {
	return []Route{
		{EnrollPattern, c.handleEnroll},
		{"POST /api/v1/agent/heartbeat", c.requireAgent(c.handleHeartbeat)},
		{"POST /api/v1/agent/jobs/next", c.requireAgent(c.handleNextJob)},
		{"POST /api/v1/agent/jobs/{id}/start", c.requireAgent(c.handleStart)},
		{"POST /api/v1/agent/jobs/{id}/progress", c.requireAgent(c.handleProgress)},
		{"POST /api/v1/agent/jobs/{id}/chunks", c.requireAgent(c.handleChunk)},
		{"POST /api/v1/agent/jobs/{id}/finish", c.requireAgent(c.handleFinish)},
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}

// RemoteIP is the agent's address as seen by the server (first X-Forwarded-For hop when the
// server sits behind a reverse proxy / tunnel, like the user-facing audit log).
func RemoteIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func bearer(r *http.Request) string {
	authz := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(authz) > 7 && strings.EqualFold(authz[:7], "Bearer ") {
		return strings.TrimSpace(authz[7:])
	}
	return ""
}

func (c *Coordinator) requireAgent(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r)
		if !strings.HasPrefix(tok, CredentialPrefix) {
			writeErr(w, http.StatusUnauthorized, "agent credential required")
			return
		}
		a, err := c.Authenticate(r.Context(), tok, RemoteIP(r))
		if err != nil {
			if errors.Is(err, ErrAgentOff) {
				writeErr(w, http.StatusForbidden, "agent is disabled on the server")
				return
			}
			writeErr(w, http.StatusUnauthorized, "invalid agent credential")
			return
		}
		inst := strings.TrimSpace(r.Header.Get(InstanceHeader))
		if inst == "" || len(inst) > 128 {
			inst = "default"
		}
		ctx := context.WithValue(r.Context(), agentCtxKey{}, agentIdentity{agent: a, instance: inst})
		next(w, r.WithContext(ctx))
	}
}

func identity(r *http.Request) agentIdentity {
	id, _ := r.Context().Value(agentCtxKey{}).(agentIdentity)
	return id
}

func decode(r *http.Request, dst any) error {
	body, closeBody, err := requestBody(r)
	if err != nil {
		return err
	}
	defer closeBody()
	return json.NewDecoder(body).Decode(dst)
}

func (c *Coordinator) writeOpErr(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, db.ErrNotFound):
		writeErr(w, http.StatusNotFound, "run not found")
	case errors.Is(err, ErrNotYourRun):
		writeErr(w, http.StatusForbidden, err.Error())
	case errors.Is(err, ErrLeased):
		writeErr(w, http.StatusConflict, err.Error())
	case errors.Is(err, ErrUnknownAgent):
		writeErr(w, http.StatusUnauthorized, err.Error())
	case errors.Is(err, ErrAgentOff):
		writeErr(w, http.StatusForbidden, err.Error())
	default:
		writeErr(w, http.StatusBadRequest, err.Error())
	}
}

func (c *Coordinator) handleEnroll(w http.ResponseWriter, r *http.Request) {
	var req EnrollRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	resp, err := c.Enroll(r.Context(), req, RemoteIP(r))
	if err != nil {
		// Same answer for unknown, expired and used tokens.
		time.Sleep(200 * time.Millisecond)
		writeErr(w, http.StatusUnauthorized, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (c *Coordinator) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	var req HeartbeatRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	id := identity(r)
	resp, err := c.Heartbeat(r.Context(), id.agent.ID, id.instance, req)
	if err != nil {
		c.writeOpErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (c *Coordinator) handleNextJob(w http.ResponseWriter, r *http.Request) {
	wait := 0
	if v := r.URL.Query().Get("wait"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			wait = n
		}
	}
	id := identity(r)
	spec, err := c.NextJob(r.Context(), id.agent.ID, id.instance, time.Duration(wait)*time.Second)
	if err != nil {
		c.writeOpErr(w, err)
		return
	}
	if spec == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, http.StatusOK, spec)
}

func (c *Coordinator) handleStart(w http.ResponseWriter, r *http.Request) {
	var req StartRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	id := identity(r)
	resp, err := c.Start(r.Context(), id.agent.ID, id.instance, r.PathValue("id"), req)
	if err != nil {
		c.writeOpErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (c *Coordinator) handleProgress(w http.ResponseWriter, r *http.Request) {
	var req ProgressRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	id := identity(r)
	resp, err := c.Progress(r.Context(), id.agent.ID, id.instance, r.PathValue("id"), req)
	if err != nil {
		c.writeOpErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (c *Coordinator) handleChunk(w http.ResponseWriter, r *http.Request) {
	var req ChunkUpload
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	id := identity(r)
	resp, err := c.UploadChunk(r.Context(), id.agent.ID, id.instance, r.PathValue("id"), req)
	if err != nil {
		c.writeOpErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (c *Coordinator) handleFinish(w http.ResponseWriter, r *http.Request) {
	var req FinishRequest
	if err := decode(r, &req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	id := identity(r)
	resp, err := c.Finish(r.Context(), id.agent.ID, id.instance, r.PathValue("id"), req)
	if err != nil {
		c.writeOpErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}
