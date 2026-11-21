package api

import (
	"encoding/json"
	"net/http"

	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/db"
	"github.com/Rei-x/agh-attack-surface-intelligence/backend/internal/domain"
)

func (s *Server) handleListSignatures(w http.ResponseWriter, r *http.Request) {
	custom, err := s.store.ListSignatures(r.Context())
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	builtins := s.pipeline.Analyzer().BuiltinSignatures()
	seen := make(map[string]bool, len(custom))
	for _, c := range custom {
		seen[c.ID] = true
	}
	all := make([]domain.Signature, 0, len(builtins)+len(custom))
	for _, b := range builtins {
		if !seen[b.ID] {
			all = append(all, b)
		}
	}
	all = append(all, custom...)
	writeJSON(w, http.StatusOK, map[string]any{"signatures": all})
}

func (s *Server) handleCreateSignature(w http.ResponseWriter, r *http.Request) {
	var sig domain.Signature
	if err := decodeJSON(r, &sig); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if err := s.pipeline.Analyzer().ValidateSignature(sig); err != nil {
		writeErr(w, http.StatusBadRequest, "signature safety validation failed: "+err.Error())
		return
	}
	if sig.MatchMode == "" {
		sig.MatchMode = "any"
	}
	if sig.Category == "" {
		sig.Category = "custom"
	}
	if sig.ConfidenceWeight <= 0 {
		sig.ConfidenceWeight = 0.75
	}
	sig.IsBuiltin = false
	sig.Enabled = true
	sig.CreatedBy = currentUsername(r)
	if err := s.store.CreateSignature(r.Context(), &sig); err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, sig)
}

func (s *Server) handleUpdateSignature(w http.ResponseWriter, r *http.Request) {
	var sig domain.Signature
	if err := decodeJSON(r, &sig); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if err := s.pipeline.Analyzer().ValidateSignature(sig); err != nil {
		writeErr(w, http.StatusBadRequest, "signature safety validation failed: "+err.Error())
		return
	}
	sig.ID = r.PathValue("id")
	if err := s.store.UpdateSignature(r.Context(), &sig); err != nil {
		writeStoreErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sig)
}

func (s *Server) handleDeleteSignature(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteSignature(r.Context(), r.PathValue("id")); err != nil {
		writeStoreErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleValidateSignature(w http.ResponseWriter, r *http.Request) {
	var sig domain.Signature
	if err := decodeJSON(r, &sig); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"valid":  false,
			"errors": []string{"invalid json payload"},
			"reason": "invalid json payload",
		})
		return
	}
	if err := s.pipeline.Analyzer().ValidateSignature(sig); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"valid":  false,
			"errors": []string{err.Error()},
			"reason": err.Error(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"valid":  true,
		"errors": []string{},
	})
}

func (s *Server) handleTestSignature(w http.ResponseWriter, r *http.Request) {
	var sig domain.Signature
	if err := decodeJSON(r, &sig); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	if err := s.pipeline.Analyzer().ValidateSignature(sig); err != nil {
		writeErr(w, http.StatusBadRequest, "signature safety validation failed: "+err.Error())
		return
	}
	services, err := s.store.ListServices(r.Context(), db.ServiceFilter{})
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	hits := s.pipeline.Analyzer().RetroactiveTest(sig, services)
	matches := make([]map[string]any, 0, len(hits))
	for _, h := range hits {
		matches = append(matches, map[string]any{
			"host_id":       h.HostID,
			"host_ip":       h.HostIP,
			"service_id":    h.ServiceID,
			"port":          h.Port,
			"protocol":      h.Protocol,
			"http_title":    h.Title,
			"version":       h.Version,
			"confidence":    h.Confidence,
			"matched_rules": h.MatchedText,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"matches":         matches,
		"tested_services": len(services),
		"total_matches":   len(matches),
	})
}

func (s *Server) handleImportSignatures(w http.ResponseWriter, r *http.Request) {
	var raw json.RawMessage
	if err := decodeJSON(r, &raw); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	var list []domain.Signature
	if err := json.Unmarshal(raw, &list); err != nil {
		var wrapper struct {
			Signatures []domain.Signature `json:"signatures"`
		}
		if err2 := json.Unmarshal(raw, &wrapper); err2 != nil {
			writeErr(w, http.StatusBadRequest, "expected JSON array or {signatures: []}")
			return
		}
		list = wrapper.Signatures
	}

	imported := 0
	rejected := []string{}
	for _, sig := range list {
		if err := s.pipeline.Analyzer().ValidateSignature(sig); err != nil {
			rejected = append(rejected, sig.Name+": "+err.Error())
			continue
		}
		sig.ID = ""
		sig.IsBuiltin = false
		sig.Enabled = true
		sig.CreatedBy = currentUsername(r)
		if sig.MatchMode == "" {
			sig.MatchMode = "any"
		}
		if err := s.store.CreateSignature(r.Context(), &sig); err == nil {
			imported++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"imported": imported,
		"rejected": rejected,
	})
}

func (s *Server) handleExportSignatures(w http.ResponseWriter, r *http.Request) {
	custom, err := s.store.ListSignatures(r.Context())
	if err != nil {
		writeStoreErr(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="aegis-asi-signatures.json"`)
	_ = json.NewEncoder(w).Encode(custom)
}
