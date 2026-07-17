package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type operationState struct {
	Plan       plan       `json:"plan"`
	Mode       string     `json:"mode"`
	Status     string     `json:"status"`
	Phases     []phase    `json:"phases"`
	StartedAt  time.Time  `json:"startedAt"`
	FinishedAt *time.Time `json:"finishedAt,omitempty"`
}

type operationStore struct{ directory string }

func newOperationStore() *operationStore {
	root, err := os.UserConfigDir()
	if err != nil || root == "" {
		root = os.TempDir()
	}
	directory := filepath.Join(root, "ApiaryLens", "ScoutBee", "operations")
	_ = os.MkdirAll(directory, 0o700)
	return &operationStore{directory: directory}
}

func (s *operationStore) path(id string) (string, error) {
	if !planID.MatchString(id) {
		return "", errors.New("invalid operation identifier")
	}
	return filepath.Join(s.directory, id+".json"), nil
}

func (s *operationStore) save(state operationState) error {
	path, err := s.path(state.Plan.PlanID)
	if err != nil {
		return err
	}
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	temp := path + ".tmp"
	if err = os.WriteFile(temp, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(temp, path)
}

func (s *operationStore) load(id string) (operationState, error) {
	path, err := s.path(id)
	if err != nil {
		return operationState{}, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return operationState{}, err
	}
	var state operationState
	if err = json.Unmarshal(raw, &state); err != nil {
		return operationState{}, err
	}
	return state, nil
}

func (e *executor) operationHTTP(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/operations/")
	if !planID.MatchString(id) {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"message": "Invalid operation identifier"})
		return
	}
	if r.Method == http.MethodPost && r.URL.Query().Get("action") == "cancel" {
		e.activeMu.Lock()
		cancel := e.active[id]
		e.activeMu.Unlock()
		if cancel == nil {
			jsonResponse(w, http.StatusConflict, map[string]string{"message": "The operation is not running"})
			return
		}
		cancel()
		jsonResponse(w, http.StatusAccepted, map[string]string{"status": "canceling"})
		return
	}
	if r.Method != http.MethodGet {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"message": "Method not allowed"})
		return
	}
	state, err := e.store.load(id)
	if err != nil {
		jsonResponse(w, http.StatusNotFound, map[string]string{"message": "Operation not found"})
		return
	}
	jsonResponse(w, http.StatusOK, state)
}

func (e *executor) diagnosticsHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"message": "Method not allowed"})
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/diagnostics/")
	state, err := e.store.load(id)
	if err != nil {
		jsonResponse(w, http.StatusNotFound, map[string]string{"message": "Operation not found"})
		return
	}
	bundle := map[string]any{
		"product": "ApiaryLens Scout Bee", "scoutVersion": scoutVersion,
		"generatedAt": time.Now().UTC(), "operation": state,
		"privacy": "This bundle contains the secret-free plan and sanitized phase output. It contains no runtime credentials.",
	}
	w.Header().Set("Content-Disposition", `attachment; filename="apiarylens-scout-diagnostics-`+id+`.json"`)
	jsonResponse(w, http.StatusOK, bundle)
}
