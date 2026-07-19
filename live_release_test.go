package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// The live release tests exercise the published ApiaryLens GitHub release end
// to end: stable-by-default discovery, preview opt-in discovery, the pinned
// manifest checksum, the redirect-restricted artifact downloads with SHA-256
// and size verification, and the GitHub attestation binding. They talk to the
// network, so they are opt-in and skipped everywhere by default; CI stays
// hermetic. Run locally with SCOUT_BEE_LIVE_RELEASE_TESTS=1 to record
// released-byte evidence.
func TestLivePublishedPreviewReleaseLifecycleEvidence(t *testing.T) {
	if os.Getenv("SCOUT_BEE_LIVE_RELEASE_TESTS") != "1" {
		t.Skip("set SCOUT_BEE_LIVE_RELEASE_TESTS=1 to exercise the published GitHub release")
	}
	executor := newExecutor()
	executor.cacheDirectory = t.TempDir()

	stableRequest := httptest.NewRequest(http.MethodGet, "/api/v1/release", nil)
	stableResponse := httptest.NewRecorder()
	executor.releaseHTTP(stableResponse, stableRequest)
	if stableResponse.Code == http.StatusOK {
		t.Fatalf("no stable ApiaryLens release has been published; stable discovery must fail closed, got %s", stableResponse.Body.String())
	}
	t.Logf("stable channel fails closed while no stable release exists: HTTP %d %s", stableResponse.Code, stableResponse.Body.String())

	optOutRequest := httptest.NewRequest(http.MethodGet, "/api/v1/release?channel=preview", nil)
	optOutResponse := httptest.NewRecorder()
	executor.releaseHTTP(optOutResponse, optOutRequest)
	if optOutResponse.Code != http.StatusForbidden {
		t.Fatalf("preview without explicit advanced opt-in must be refused, got %d", optOutResponse.Code)
	}

	previewRequest := httptest.NewRequest(http.MethodGet, "/api/v1/release?channel=preview&advanced=true", nil)
	previewResponse := httptest.NewRecorder()
	executor.releaseHTTP(previewResponse, previewRequest)
	if previewResponse.Code != http.StatusOK {
		t.Fatalf("preview discovery against the published release failed: %d %s", previewResponse.Code, previewResponse.Body.String())
	}
	var identity release
	if err := json.Unmarshal(previewResponse.Body.Bytes(), &identity); err != nil {
		t.Fatal(err)
	}
	if identity.Version != "0.1.0-preview.6" || identity.Channel != "preview" {
		t.Fatalf("unexpected published preview identity: %+v", identity)
	}
	t.Logf("preview discovery pinned %s (%s) manifest SHA-256 %s", identity.Version, identity.Channel, identity.ManifestSha256)

	ctx := context.Background()
	manifest, err := executor.fetchManifest(ctx, identity)
	if err != nil {
		t.Fatalf("pinned manifest verification failed: %v", err)
	}
	for _, target := range []string{"compose", "cloudflare"} {
		artifact, artifactErr := artifactFor(manifest, target)
		if artifactErr != nil {
			t.Fatalf("release has no %s deployment bundle: %v", target, artifactErr)
		}
		path, downloadErr := executor.downloadVerifiedArtifact(ctx, manifest, artifact, t.TempDir())
		if downloadErr != nil {
			t.Fatalf("%s bundle download and verification failed: %v", target, downloadErr)
		}
		info, statErr := os.Stat(path)
		if statErr != nil || info.Size() != artifact.Bytes {
			t.Fatalf("%s bundle size mismatch after verification: %v", target, statErr)
		}
		detail, attestationErr := executor.verifyArtifactAttestation(ctx, artifact)
		if attestationErr != nil {
			t.Fatalf("%s bundle attestation verification failed: %v", target, attestationErr)
		}
		t.Logf("%s bundle %s: SHA-256 %s (%d bytes) verified; %s", target, artifact.Name, artifact.Sha256, artifact.Bytes, detail)
	}
}
