package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func diagnosticWindowsState(t *testing.T) operationState {
	t.Helper()
	p := validPlan()
	p.Target = "windows-client"
	p.Cloudflare = nil
	p.WindowsClient = &windowsClient{Architecture: "x64"}
	manifest := &releaseManifest{
		Product: "ApiaryLens", ProductVersion: p.Release.Version, Channel: p.Release.Channel,
		SourceCommit: strings.Repeat("a", 40), BuildTime: "2026-07-17T16:00:00Z",
		Contracts: manifestContracts{APIVersion: "1.0.0", Sync: 1, DatabaseMigration: "0004", DeploymentPlan: 1},
		Artifacts: []manifestArtifact{
			{
				Name: `C:\Users\Alice\secret-photo.jpg`, Kind: "windows-package-manifest", Target: windowsTarget,
				URL: "https://downloads.example/package?token=runtime-token", Sha256: strings.Repeat("b", 64), Bytes: 2048,
			},
			{
				Name: "apiarylens.nupkg", Kind: "windows-package-artifact", Target: windowsTarget,
				URL: "https://downloads.example/apiarylens.nupkg", Sha256: strings.Repeat("c", 64), Bytes: 4096,
			},
		},
	}
	finished := time.Date(2026, 7, 17, 16, 5, 0, 0, time.UTC)
	return operationState{
		Plan: p, Mode: "apply", Status: "passed",
		StartedAt: finished.Add(-5 * time.Minute), FinishedAt: &finished,
		Phases: []phase{
			{Name: "Check release identity", State: "passed", Detail: `read C:\Users\Alice\hives\Clover\queen-photo.jpg using runtime-token`},
			{Name: "Verify Windows setup signature", State: "passed", Detail: "Alice's hive and media verified"},
			{Name: "untrusted Alice hive phase", State: "passed", Detail: "must be omitted"},
		},
		Verification: buildReleaseVerification(p.Release, manifest),
	}
}

func TestDiagnosticsBundleContainsOnlyAllowListedWindowsEvidence(t *testing.T) {
	state := diagnosticWindowsState(t)
	bundle, err := buildDiagnosticsBundle(state, time.Date(2026, 7, 17, 17, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, required := range []string{
		`"schemaVersion":1`, `"target":"windows-client"`, `"release_identity_verified"`,
		`"setup_authenticode_verified"`, strings.Repeat("b", 64), strings.Repeat("c", 64),
		`"manifestVerified":true`, `"sanitized":true`,
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("diagnostics omitted required evidence %q: %s", required, text)
		}
	}
	for _, forbidden := range []string{
		"Alice", "Clover", "queen-photo.jpg", "runtime-token", "downloads.example",
		"artifactIdentity", "manifestUrl", `"detail"`, `"plan"`,
	} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("diagnostics exposed forbidden content %q: %s", forbidden, text)
		}
	}
	if len(bundle.Operation.Checks) != 2 {
		t.Fatalf("unknown phase names must be dropped, got %+v", bundle.Operation.Checks)
	}
}

func TestDiagnosticsDropsTamperedReleaseMetadata(t *testing.T) {
	state := diagnosticWindowsState(t)
	state.Verification.SourceCommit = `C:\Users\Alice\token.txt`
	state.Verification.BuildTime = "hive Clover"
	state.Verification.Contracts.API = "secret-token"
	state.Verification.Artifacts = append(state.Verification.Artifacts, diagnosticArtifactVerification{
		Kind: "private-media", Target: windowsTarget, Sha256: strings.Repeat("d", 64), Bytes: 123,
	})
	bundle, err := buildDiagnosticsBundle(state, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(bundle)
	text := string(raw)
	for _, forbidden := range []string{"Alice", "Clover", "secret-token", "private-media", strings.Repeat("d", 64)} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("tampered metadata entered diagnostics: %q in %s", forbidden, text)
		}
	}
	if bundle.ReleaseVerification.SourceCommit != "" || bundle.ReleaseVerification.BuildTime != "" || bundle.ReleaseVerification.Contracts.API != "" {
		t.Fatalf("tampered scalar metadata was not dropped: %+v", bundle.ReleaseVerification)
	}
}

func TestDiagnosticsHTTPDownloadsSanitizedBundle(t *testing.T) {
	state := diagnosticWindowsState(t)
	store := &operationStore{directory: t.TempDir()}
	if err := store.save(state); err != nil {
		t.Fatal(err)
	}
	executor := &executor{store: store}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/diagnostics/"+state.Plan.PlanID, nil)
	response := httptest.NewRecorder()
	executor.diagnosticsHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("unexpected status %d: %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Header().Get("Content-Disposition"), state.Plan.PlanID+".json") ||
		response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unexpected diagnostics headers: %v", response.Header())
	}
	if strings.Contains(response.Body.String(), "runtime-token") || strings.Contains(response.Body.String(), `C:\Users\Alice`) {
		t.Fatalf("HTTP diagnostics exposed private content: %s", response.Body.String())
	}
}

func TestDiagnosticsRefusesNonWindowsOperation(t *testing.T) {
	state := diagnosticWindowsState(t)
	state.Plan.Target = "cloudflare"
	state.Plan.WindowsClient = nil
	state.Plan.Cloudflare = &cloudflare{}
	if _, err := buildDiagnosticsBundle(state, time.Now()); err == nil {
		t.Fatal("expected non-Windows diagnostics to be refused")
	}
}
