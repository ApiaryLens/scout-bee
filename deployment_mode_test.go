package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func boolPointer(value bool) *bool { return &value }

func TestWebFrontendSelectionDefaultsToLegacyWebAndPreservesBackendOnly(t *testing.T) {
	if !webFrontendEnabled(nil) || !webFrontendEnabled(boolPointer(true)) {
		t.Fatal("legacy and explicit web plans must include the web application")
	}
	if webFrontendEnabled(boolPointer(false)) {
		t.Fatal("an explicit backend-only plan must not include the web application")
	}

	original := plan{
		SchemaVersion: 1,
		Target:        "cloudflare",
		Cloudflare: &cloudflare{
			WorkerName:         "apiarylens-family",
			IncludeWebFrontend: boolPointer(false),
		},
	}
	raw, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "secret") {
		t.Fatalf("deployment selection introduced a secret-bearing field: %s", raw)
	}
	var decoded plan
	if err = json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Cloudflare == nil || webFrontendEnabled(decoded.Cloudflare.IncludeWebFrontend) {
		t.Fatalf("backend-only selection did not survive plan serialization: %s", raw)
	}
}

func TestCloudflareWranglerConfigOmitsAssetsOnlyForBackendOnlyPlans(t *testing.T) {
	manifest := releaseManifest{
		ProductVersion: "0.1.0-preview.1",
		SourceCommit:   strings.Repeat("a", 40),
		BuildTime:      "2026-07-17T18:00:00Z",
	}
	base := cloudflare{
		AccountReference: "01234567890123456789012345678901",
		WorkerName:       "apiarylens-family",
		D1DatabaseName:   "apiarylens-family",
		R2BucketName:     "apiarylens-family-media",
		CostProfile:      "family-free-guarded",
	}

	withWeb := cloudflareWranglerConfig(plan{Cloudflare: &base}, manifest, "database-id", true)
	if _, ok := withWeb["assets"]; !ok {
		t.Fatal("legacy Cloudflare plans must retain PWA assets")
	}

	base.IncludeWebFrontend = boolPointer(false)
	backendOnly := cloudflareWranglerConfig(plan{Cloudflare: &base}, manifest, "database-id", true)
	if _, ok := backendOnly["assets"]; ok {
		t.Fatal("backend-only Cloudflare plans must omit public PWA assets")
	}
	for _, binding := range []string{"d1_databases", "r2_buckets"} {
		if _, ok := backendOnly[binding]; !ok {
			t.Fatalf("backend-only Cloudflare plans must retain %s", binding)
		}
	}
}

func TestComposeBackendOnlyUsesDedicatedProxyConfiguration(t *testing.T) {
	for _, required := range []string{
		"include_web_frontend=${14}",
		"caddyfile=Caddyfile.backend-only",
		"APIARYLENS_CADDYFILE=%s",
	} {
		if !strings.Contains(composeRemoteScript, required) {
			t.Fatalf("Compose backend-only lifecycle is missing %q", required)
		}
	}
}
