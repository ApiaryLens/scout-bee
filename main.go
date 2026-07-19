package main

import (
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

//go:embed ui-dist/*
var ui embed.FS

func main() {
	if handled, exitCode := runSSHAskpass(os.Stdout); handled {
		os.Exit(exitCode)
	}
	token := randomToken()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	assets, err := fs.Sub(ui, "ui-dist")
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/status", authorized(token, func(w http.ResponseWriter, _ *http.Request) {
		jsonResponse(w, http.StatusOK, statusPayload())
	}))
	executor := newExecutor()
	mux.HandleFunc("/api/v1/release", authorized(token, executor.releaseHTTP))
	mux.HandleFunc("/api/v1/scout-update", authorized(token, executor.scoutUpdateHTTP))
	mux.HandleFunc("/api/v1/local/folder-check", authorized(token, executor.localFolderCheckHTTP))
	mux.HandleFunc("/api/v1/execute", authorized(token, executor.executeHTTP))
	mux.HandleFunc("/api/v1/history", authorized(token, executor.historyHTTP))
	mux.HandleFunc("/api/v1/operations/", authorized(token, executor.operationHTTP))
	mux.HandleFunc("/api/v1/diagnostics/", authorized(token, executor.diagnosticsHTTP))
	mux.Handle("/", securityHeaders(http.FileServer(http.FS(assets))))
	url := fmt.Sprintf("http://%s/#%s", listener.Addr(), token)
	fmt.Printf("Scout Bee is ready at %s\n", strings.Split(url, "#")[0])
	openBrowser(url)
	server := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Fatal(server.Serve(listener))
}

// statusPayload reports launch readiness plus the capabilities the guide UI
// may offer. windowsClientEnabled defaults to false (ADR 0023 bootstrap scope);
// the UI hides the Windows client target unless the flag is explicitly set.
func statusPayload() map[string]any {
	return map[string]any{
		"status":               "ready",
		"version":              scoutVersion,
		"windowsClientEnabled": windowsClientEnabled(),
	}
}

func authorized(token string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(provided), []byte(token)) != 1 {
			jsonResponse(w, http.StatusUnauthorized, map[string]string{"message": "Scout Bee launch authorization is required"})
			return
		}
		next(w, r)
	}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func jsonResponse(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func randomToken() string {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(value)
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}
