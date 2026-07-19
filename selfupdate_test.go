package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewerScoutVersionOrdering(t *testing.T) {
	cases := []struct {
		current, candidate string
		newer              bool
	}{
		{"0.1.0-preview.4", "0.1.0", true},
		{"0.1.0-preview.4", "0.1.0-rc.1", true},
		{"0.1.0-preview.4", "0.1.0-preview.5", true},
		{"0.1.0-preview.4", "0.1.0-preview.4", false},
		{"0.1.0-preview.4", "0.1.0-preview.3", false},
		{"0.1.0", "0.1.0", false},
		{"0.1.0", "0.1.0-rc.9", false},
		{"0.1.0", "0.1.1", true},
		{"0.1.0", "0.2.0-preview.1", true},
		{"0.2.0", "0.1.9", false},
		{"0.1.0", "1.0.0", true},
	}
	for _, current := range cases {
		if got := newerScoutVersion(current.current, current.candidate); got != current.newer {
			t.Fatalf("newerScoutVersion(%q, %q) = %v, want %v", current.current, current.candidate, got, current.newer)
		}
	}
}

func scoutUpdateFeedServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func TestScoutUpdateCheckReportsNewerStableWithVerifiedDigest(t *testing.T) {
	original := officialScoutReleaseFeedURL
	defer func() { officialScoutReleaseFeedURL = original }()
	digest := "sha256:" + fmt.Sprintf("%064d", 7)
	server := scoutUpdateFeedServer(t, http.StatusOK, `{
		"tag_name": "v9.9.9", "html_url": "https://github.com/ApiaryLens/scout-bee/releases/tag/v9.9.9",
		"draft": false, "prerelease": false,
		"assets": [
			{"name": "ScoutBeeSetup.exe", "digest": "`+digest+`"},
			{"name": "scout-bee-linux.tar.gz", "digest": "`+digest+`"}
		]
	}`)
	defer server.Close()
	officialScoutReleaseFeedURL = server.URL
	status := (&executor{client: server.Client()}).checkScoutUpdate(context.Background())
	if !status.UpdateAvailable || status.LatestVersion != "9.9.9" || status.CurrentVersion != scoutVersion {
		t.Fatalf("expected an available newer stable, got %+v", status)
	}
	if status.ReleaseURL != "https://github.com/ApiaryLens/scout-bee/releases/tag/v9.9.9" {
		t.Fatalf("release link must point at the official release page: %+v", status)
	}
	if status.AssetName == "" || status.AssetSha256 != fmt.Sprintf("%064d", 7) {
		t.Fatalf("expected a platform asset with its published SHA-256, got %+v", status)
	}
}

func TestScoutUpdateCheckFailsQuietly(t *testing.T) {
	original := officialScoutReleaseFeedURL
	defer func() { officialScoutReleaseFeedURL = original }()
	cases := map[string]struct {
		status int
		body   string
	}{
		"no stable release": {http.StatusNotFound, `{"message": "Not Found"}`},
		"prerelease latest": {http.StatusOK, `{"tag_name":"v9.9.9","html_url":"https://github.com/ApiaryLens/scout-bee/releases/tag/v9.9.9","prerelease":true}`},
		"draft latest":      {http.StatusOK, `{"tag_name":"v9.9.9","html_url":"https://github.com/ApiaryLens/scout-bee/releases/tag/v9.9.9","draft":true}`},
		"same version":      {http.StatusOK, `{"tag_name":"v` + scoutVersion + `","html_url":"https://github.com/ApiaryLens/scout-bee/releases/tag/x"}`},
		"unparsable feed":   {http.StatusOK, `not json`},
		"insecure link":     {http.StatusOK, `{"tag_name":"v9.9.9","html_url":"http://example.com"}`},
		"rate limited":      {http.StatusForbidden, `{"message":"rate limited"}`},
		"empty tag":         {http.StatusOK, `{"tag_name":"","html_url":"https://github.com/ApiaryLens/scout-bee"}`},
	}
	for name, current := range cases {
		server := scoutUpdateFeedServer(t, current.status, current.body)
		officialScoutReleaseFeedURL = server.URL
		status := (&executor{client: server.Client()}).checkScoutUpdate(context.Background())
		server.Close()
		if status.UpdateAvailable {
			t.Fatalf("%s must fail quietly, got %+v", name, status)
		}
		if status.CurrentVersion != scoutVersion {
			t.Fatalf("%s must still report the current version, got %+v", name, status)
		}
	}
	offline := &executor{client: http.DefaultClient}
	officialScoutReleaseFeedURL = "https://127.0.0.1:1/releases/latest"
	if status := offline.checkScoutUpdate(context.Background()); status.UpdateAvailable {
		t.Fatalf("offline check must fail quietly, got %+v", status)
	}
}
