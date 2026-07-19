package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEmbeddedCompatibilitySupportsOnlyExplicitlyTestedProducts(t *testing.T) {
	compatibility, err := loadCompatibility()
	if err != nil {
		t.Fatal(err)
	}
	if compatibility.ScoutVersion != scoutVersion {
		t.Fatalf("embedded Scout identity %q does not match executable %q", compatibility.ScoutVersion, scoutVersion)
	}
	if !compatibleProductVersion("0.1.0-preview.6") {
		t.Fatal("the current tested product version must be supported")
	}
	for _, unsupported := range []string{"0.1.0-preview.1", "0.1.0-preview.3", "0.1.0-preview.5", "0.1.1", "0.1.99-rc.1", "0.2.0"} {
		if compatibleProductVersion(unsupported) {
			t.Fatalf("untested product version %q must fail closed", unsupported)
		}
	}
}

func TestPinnedManifestExecutionRejectsUntestedProductVersion(t *testing.T) {
	raw := []byte(`{"product":"ApiaryLens","productVersion":"0.1.0-preview.1","channel":"preview","contracts":{"deploymentPlan":1},"artifacts":[]}`)
	digest := sha256.Sum256(raw)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(raw)
	}))
	defer server.Close()

	executor := &executor{client: server.Client(), allowLoopback: true}
	_, err := executor.fetchManifest(context.Background(), release{
		Version:        "0.1.0-preview.1",
		Channel:        "preview",
		ManifestURL:    server.URL,
		ManifestSha256: hex.EncodeToString(digest[:]),
	})
	if err == nil || !strings.Contains(err.Error(), "compatibility") {
		t.Fatalf("expected untested pinned manifest to fail compatibility, got %v", err)
	}
}

func TestPinnedManifestExecutionAcceptsExplicitlySupportedProductVersion(t *testing.T) {
	raw := []byte(`{"product":"ApiaryLens","productVersion":"0.1.0-preview.6","channel":"preview","contracts":{"deploymentPlan":1},"artifacts":[]}`)
	digest := sha256.Sum256(raw)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(raw)
	}))
	defer server.Close()

	executor := &executor{client: server.Client(), allowLoopback: true}
	manifest, err := executor.fetchManifest(context.Background(), release{
		Version:        "0.1.0-preview.6",
		Channel:        "preview",
		ManifestURL:    server.URL,
		ManifestSha256: hex.EncodeToString(digest[:]),
	})
	if err != nil {
		t.Fatalf("expected supported pinned manifest to pass: %v", err)
	}
	if manifest.ProductVersion != "0.1.0-preview.6" {
		t.Fatalf("unexpected supported product identity: %+v", manifest)
	}
}

func TestReleaseDiscoveryRejectsUntestedProductVersion(t *testing.T) {
	original := officialReleaseManifestURLs
	defer func() { officialReleaseManifestURLs = original }()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"product":"ApiaryLens","productVersion":"0.1.0-preview.1","channel":"preview","contracts":{"deploymentPlan":1},"artifacts":[]}`))
	}))
	defer server.Close()
	officialReleaseManifestURLs = map[string]string{"preview": server.URL}

	executor := &executor{client: server.Client()}
	request := httptest.NewRequest(http.MethodGet, "/api/v1/release?channel=preview&advanced=true", nil)
	response := httptest.NewRecorder()
	executor.releaseHTTP(response, request)
	if response.Code != http.StatusBadGateway || !strings.Contains(response.Body.String(), "incompatible") {
		t.Fatalf("expected untested discovery to fail closed, got %d %s", response.Code, response.Body.String())
	}
}
