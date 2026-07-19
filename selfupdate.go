package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Scout's own update model (ADR 0023): Scout is run-on-demand and never
// updates itself or runs anything in the background. On launch the UI asks
// this endpoint once whether a newer *stable* Scout release exists; the check
// fails quietly offline and the answer is only ever a non-blocking notice
// with a verified download link. Self-replacement is deliberately deferred —
// winget/choco handle Scout upgrades once stable ships.
var officialScoutReleaseFeedURL = "https://api.github.com/repos/ApiaryLens/scout-bee/releases/latest"

type scoutUpdateStatus struct {
	UpdateAvailable bool   `json:"updateAvailable"`
	CurrentVersion  string `json:"currentVersion"`
	LatestVersion   string `json:"latestVersion,omitempty"`
	ReleaseURL      string `json:"releaseUrl,omitempty"`
	AssetName       string `json:"assetName,omitempty"`
	AssetSha256     string `json:"assetSha256,omitempty"`
}

func (e *executor) scoutUpdateHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"message": "Method not allowed"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	jsonResponse(w, http.StatusOK, e.checkScoutUpdate(ctx))
}

// checkScoutUpdate returns quietly (updateAvailable=false) on every failure:
// offline, rate-limited, unparsable feeds, or prerelease-only feeds.
func (e *executor) checkScoutUpdate(ctx context.Context) scoutUpdateStatus {
	status := scoutUpdateStatus{CurrentVersion: scoutVersion}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, officialScoutReleaseFeedURL, nil)
	if err != nil {
		return status
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	response, err := e.client.Do(request)
	if err != nil {
		return status
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return status
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return status
	}
	var feed struct {
		TagName    string `json:"tag_name"`
		HTMLURL    string `json:"html_url"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
		Assets     []struct {
			Name   string `json:"name"`
			Digest string `json:"digest"`
		} `json:"assets"`
	}
	if json.Unmarshal(raw, &feed) != nil || feed.Draft || feed.Prerelease {
		return status
	}
	latest := strings.TrimPrefix(feed.TagName, "v")
	if latest == "" || !newerScoutVersion(scoutVersion, latest) || !safeHTTPSURL(feed.HTMLURL) {
		return status
	}
	status.UpdateAvailable = true
	status.LatestVersion = latest
	status.ReleaseURL = feed.HTMLURL
	wantSuffix := ".tar.gz"
	if runtime.GOOS == "windows" {
		wantSuffix = ".exe"
	}
	for _, asset := range feed.Assets {
		if !strings.HasSuffix(strings.ToLower(asset.Name), wantSuffix) {
			continue
		}
		status.AssetName = asset.Name
		digest := strings.TrimPrefix(asset.Digest, "sha256:")
		if digest != asset.Digest && validSha256(digest) {
			status.AssetSha256 = strings.ToLower(digest)
		}
		break
	}
	return status
}

// newerScoutVersion reports whether candidate is a strictly newer Scout
// version than current, using the release ordering preview < rc < stable for
// an equal numeric base.
func newerScoutVersion(current, candidate string) bool {
	currentBase, currentStage, currentOrdinal := splitScoutVersion(current)
	candidateBase, candidateStage, candidateOrdinal := splitScoutVersion(candidate)
	for index := 0; index < 3; index++ {
		if candidateBase[index] != currentBase[index] {
			return candidateBase[index] > currentBase[index]
		}
	}
	if candidateStage != currentStage {
		return candidateStage > currentStage
	}
	return candidateOrdinal > currentOrdinal
}

func splitScoutVersion(version string) ([3]int, int, int) {
	base, pre, _ := strings.Cut(version, "-")
	var numbers [3]int
	for index, part := range strings.SplitN(base, ".", 3) {
		if index < 3 {
			numbers[index], _ = strconv.Atoi(part)
		}
	}
	stage := 2 // stable
	ordinal := 0
	switch {
	case strings.HasPrefix(pre, "preview."):
		stage = 0
		ordinal, _ = strconv.Atoi(strings.TrimPrefix(pre, "preview."))
	case strings.HasPrefix(pre, "rc."):
		stage = 1
		ordinal, _ = strconv.Atoi(strings.TrimPrefix(pre, "rc."))
	case pre != "":
		stage = -1 // unknown prerelease sorts below everything released
	}
	return numbers, stage, ordinal
}
