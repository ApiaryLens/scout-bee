package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type command struct {
	Executable  string
	Args        []string
	Directory   string
	Stdin       []byte
	Environment map[string]string
}

type commandRunner interface {
	Run(context.Context, command, map[string]string) (string, error)
	Find(string) error
}

type systemRunner struct{}

var officialReleaseManifestURLs = map[string]string{
	"stable":            "https://apiarylens.org/releases/stable/manifest.json",
	"release-candidate": "https://apiarylens.org/releases/release-candidate/manifest.json",
	"preview":           "https://apiarylens.org/releases/0.1.0-preview.1/manifest.json",
}

var allowedExecutables = map[string]bool{
	"wrangler": true, "ssh": true, "scp": true, "ssh-keyscan": true,
}

func (systemRunner) Find(name string) error {
	if !allowedExecutables[name] {
		return fmt.Errorf("executable %q is not allowed", name)
	}
	_, err := exec.LookPath(name)
	return err
}

func (e *executor) releaseHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"message": "Method not allowed"})
		return
	}
	channel := r.URL.Query().Get("channel")
	if channel == "" {
		channel = "stable"
	}
	manifestURL, knownChannel := officialReleaseManifestURLs[channel]
	if !knownChannel {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"message": "The requested release channel is unsupported"})
		return
	}
	if channel != "stable" && r.URL.Query().Get("advanced") != "true" {
		jsonResponse(w, http.StatusForbidden, map[string]string{"message": "Preview and release-candidate channels require explicit advanced opt-in"})
		return
	}
	request, err := http.NewRequestWithContext(r.Context(), http.MethodGet, manifestURL, nil)
	if err != nil {
		jsonResponse(w, http.StatusBadGateway, map[string]string{"message": "The official release identity is unavailable"})
		return
	}
	response, err := e.client.Do(request)
	if err != nil || response.StatusCode != http.StatusOK {
		jsonResponse(w, http.StatusBadGateway, map[string]string{"message": "The official release identity is unavailable"})
		return
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		jsonResponse(w, http.StatusBadGateway, map[string]string{"message": "The official release identity is unreadable"})
		return
	}
	var manifest releaseManifest
	if err = json.Unmarshal(raw, &manifest); err != nil || manifest.Product != "ApiaryLens" || manifest.Channel != channel || !compatibleProductVersion(manifest.ProductVersion) {
		jsonResponse(w, http.StatusBadGateway, map[string]string{"message": "The official release identity is incompatible"})
		return
	}
	digest := sha256.Sum256(raw)
	jsonResponse(w, http.StatusOK, release{
		Version: manifest.ProductVersion, Channel: manifest.Channel,
		ManifestURL: manifestURL, ManifestSha256: hex.EncodeToString(digest[:]),
	})
}

func (systemRunner) Run(ctx context.Context, spec command, secrets map[string]string) (string, error) {
	if !allowedExecutables[spec.Executable] {
		return "", fmt.Errorf("executable %q is not allowed", spec.Executable)
	}
	path, err := exec.LookPath(spec.Executable)
	if err != nil {
		return "", err
	}
	cmd := exec.CommandContext(ctx, path, spec.Args...)
	cmd.Dir = spec.Directory
	if spec.Stdin != nil {
		cmd.Stdin = strings.NewReader(string(spec.Stdin))
	}
	cmd.Env = os.Environ()
	for key, value := range spec.Environment {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	out, runErr := cmd.CombinedOutput()
	clean := redact(string(out), secrets)
	if runErr != nil {
		return clean, fmt.Errorf("%s failed: %w", spec.Executable, runErr)
	}
	return clean, nil
}

type executor struct {
	runner                commandRunner
	client                *http.Client
	allowLoopback         bool
	store                 *operationStore
	cacheDirectory        string
	windows               windowsLifecycleSystem
	windowsStateDirectory string
	activeMu              sync.Mutex
	active                map[string]context.CancelFunc
}

type executionResult struct {
	Phases            []phase
	Manifest          *releaseManifest
	ConnectionBackend string
}

func newExecutor() *executor {
	cacheRoot, err := os.UserCacheDir()
	if err != nil || cacheRoot == "" {
		cacheRoot = os.TempDir()
	}
	cacheDirectory := filepath.Join(cacheRoot, "ApiaryLens", "ScoutBee", "releases")
	_ = os.MkdirAll(cacheDirectory, 0o700)
	return &executor{
		runner:         systemRunner{},
		store:          newOperationStore(),
		active:         map[string]context.CancelFunc{},
		cacheDirectory: cacheDirectory,
		client: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("release downloads may not redirect")
		}},
	}
}

func (e *executor) executeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"message": "Method not allowed"})
		return
	}
	var input request
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"message": "The deployment request is invalid"})
		return
	}
	if input.Mode == "resume" {
		previous, loadErr := e.store.load(input.Plan.PlanID)
		if loadErr != nil || previous.Status == "passed" {
			jsonResponse(w, http.StatusConflict, map[string]string{"message": "Only a stopped or failed operation can be resumed"})
			return
		}
		if previous.Plan.Release.ManifestSha256 != input.Plan.Release.ManifestSha256 || previous.Plan.Target != input.Plan.Target || previous.Plan.Operation != input.Plan.Operation {
			jsonResponse(w, http.StatusConflict, map[string]string{"message": "Resume requires the same target, operation, and pinned release"})
			return
		}
	}
	ctx, cancel := context.WithCancel(r.Context())
	e.activeMu.Lock()
	if _, exists := e.active[input.Plan.PlanID]; exists {
		e.activeMu.Unlock()
		cancel()
		jsonResponse(w, http.StatusConflict, map[string]string{"message": "This deployment plan is already running"})
		return
	}
	e.active[input.Plan.PlanID] = cancel
	e.activeMu.Unlock()
	defer func() {
		cancel()
		e.activeMu.Lock()
		delete(e.active, input.Plan.PlanID)
		e.activeMu.Unlock()
	}()
	started := time.Now().UTC()
	_ = e.store.save(operationState{Plan: input.Plan, Mode: input.Mode, Status: "running", StartedAt: started})
	result, err := e.runDetailed(ctx, input)
	phases := result.Phases
	status := "passed"
	if errors.Is(ctx.Err(), context.Canceled) {
		status = "canceled"
	} else if err != nil {
		status = "failed"
	}
	finished := time.Now().UTC()
	_ = e.store.save(operationState{Plan: input.Plan, Mode: input.Mode, Status: status, Phases: phases, StartedAt: started, FinishedAt: &finished})
	if err != nil && len(phases) == 0 {
		jsonResponse(w, http.StatusBadRequest, map[string]string{"message": err.Error()})
		return
	}
	response := map[string]any{"phases": phases}
	if status == "passed" && input.Mode != "dry-run" && result.Manifest != nil {
		if profile := buildWindowsConnectionProfile(input.Plan, *result.Manifest, result.ConnectionBackend, finished); profile != nil {
			response["connectionProfile"] = profile
		}
	}
	jsonResponse(w, http.StatusOK, response)
}

func (e *executor) run(ctx context.Context, input request) ([]phase, error) {
	result, err := e.runDetailed(ctx, input)
	return result.Phases, err
}

func (e *executor) runDetailed(ctx context.Context, input request) (executionResult, error) {
	if input.Mode != "dry-run" && input.Mode != "apply" && input.Mode != "resume" {
		return executionResult{}, errors.New("mode must be dry-run, apply, or resume")
	}
	if err := validate(input.Plan); err != nil {
		return executionResult{}, err
	}
	phases := []phase{{Name: "Validate deployment plan", State: "passed", Detail: "The versioned plan contains no secret values."}}
	manifest, err := e.fetchManifest(ctx, input.Plan.Release)
	if err != nil {
		return executionResult{Phases: append(phases, failed("Check release identity", err))}, err
	}
	phases = append(phases, phase{Name: "Check release identity", State: "passed", Detail: fmt.Sprintf("Verified ApiaryLens %s and its pinned manifest SHA-256.", manifest.ProductVersion)})

	var adapter targetAdapter
	var cloudflareTarget *cloudflareAdapter
	if input.Plan.Target == "cloudflare" {
		cloudflareTarget = &cloudflareAdapter{executor: e}
		adapter = cloudflareTarget
	} else if input.Plan.Target == "windows-client" {
		adapter = &windowsClientAdapter{executor: e}
	} else {
		adapter = &composeAdapter{executor: e}
	}
	preflightPhases, err := adapter.preflight(ctx, input)
	phases = append(phases, preflightPhases...)
	if err != nil || input.Mode == "dry-run" {
		return executionResult{Phases: phases, Manifest: &manifest}, err
	}
	if input.Plan.Target == "cloudflare" && input.Secrets["cloudflareApiToken"] == "" {
		err = errors.New("a Cloudflare API token is required at apply time")
		return executionResult{Phases: append(phases, failed("Acquire runtime credentials", err)), Manifest: &manifest}, err
	}
	applyPhases, err := adapter.apply(ctx, input, manifest)
	phases = append(phases, applyPhases...)
	backend := ""
	if err == nil && input.Plan.Target == "compose-ssh" && input.Plan.Compose != nil {
		backend = input.Plan.Compose.PublicURL
	} else if err == nil && cloudflareTarget != nil {
		backend = cloudflareTarget.deployedAddress
	}
	return executionResult{Phases: phases, Manifest: &manifest, ConnectionBackend: backend}, err
}

type targetAdapter interface {
	preflight(context.Context, request) ([]phase, error)
	apply(context.Context, request, releaseManifest) ([]phase, error)
}

func (e *executor) fetchManifest(ctx context.Context, expected release) (releaseManifest, error) {
	if !safeHTTPSURL(expected.ManifestURL) && !(e.allowLoopback && loopbackHTTPURL(expected.ManifestURL)) {
		return releaseManifest{}, errors.New("release manifest URL is not trusted")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, expected.ManifestURL, nil)
	if err != nil {
		return releaseManifest{}, err
	}
	response, err := e.client.Do(req)
	if err != nil {
		return releaseManifest{}, fmt.Errorf("could not download the release manifest: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return releaseManifest{}, fmt.Errorf("release manifest returned HTTP %d", response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	if err != nil {
		return releaseManifest{}, err
	}
	digest := sha256.Sum256(raw)
	if !strings.EqualFold(hex.EncodeToString(digest[:]), expected.ManifestSha256) {
		return releaseManifest{}, errors.New("release manifest checksum verification failed")
	}
	var manifest releaseManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return releaseManifest{}, errors.New("release manifest is not valid JSON")
	}
	if manifest.Product != "ApiaryLens" || manifest.ProductVersion != expected.Version || manifest.Channel != expected.Channel || manifest.Contracts.DeploymentPlan != 1 {
		return releaseManifest{}, errors.New("release manifest identity or compatibility does not match the plan")
	}
	for _, artifact := range manifest.Artifacts {
		if artifact.Name == "" || artifact.Kind == "" || artifact.Target == "" || !validSha256(artifact.Sha256) || artifact.Bytes <= 0 ||
			(!safeHTTPSURL(artifact.URL) && !(e.allowLoopback && loopbackHTTPURL(artifact.URL))) {
			return releaseManifest{}, fmt.Errorf("release artifact %q is incomplete or unsafe", artifact.Name)
		}
	}
	return manifest, nil
}

func (e *executor) downloadArtifact(ctx context.Context, artifact manifestArtifact, directory string) (string, error) {
	destinationDirectory := directory
	if e.cacheDirectory != "" {
		destinationDirectory = e.cacheDirectory
	}
	if err := os.MkdirAll(destinationDirectory, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(destinationDirectory, strings.ToLower(artifact.Sha256)+"-"+filepath.Base(artifact.Name))
	if cachedArtifactMatches(path, artifact) {
		return path, nil
	}
	_ = os.Remove(path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, artifact.URL, nil)
	if err != nil {
		return "", err
	}
	response, err := e.client.Do(req)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("artifact download returned HTTP %d", response.StatusCode)
	}
	if response.ContentLength > 0 && response.ContentLength != artifact.Bytes {
		return "", errors.New("artifact size does not match the release manifest")
	}
	file, err := os.CreateTemp(destinationDirectory, ".apiarylens-download-*")
	if err != nil {
		return "", err
	}
	temporaryPath := file.Name()
	defer os.Remove(temporaryPath)
	if err = file.Chmod(0o600); err != nil {
		_ = file.Close()
		return "", err
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(file, hash), io.LimitReader(response.Body, artifact.Bytes+1))
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil {
		return "", errors.Join(copyErr, closeErr)
	}
	if written != artifact.Bytes || !strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), artifact.Sha256) {
		return "", errors.New("artifact size or checksum verification failed")
	}
	if err = os.Rename(temporaryPath, path); err != nil {
		return "", err
	}
	return path, nil
}

func cachedArtifactMatches(path string, artifact manifestArtifact) bool {
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != artifact.Bytes {
		return false
	}
	hash := sha256.New()
	if _, err = io.Copy(hash, file); err != nil {
		return false
	}
	return strings.EqualFold(hex.EncodeToString(hash.Sum(nil)), artifact.Sha256)
}

func artifactFor(manifest releaseManifest, target string) (manifestArtifact, error) {
	for _, artifact := range manifest.Artifacts {
		if artifact.Target == target && artifact.Kind == "deployment-bundle" {
			return artifact, nil
		}
	}
	return manifestArtifact{}, fmt.Errorf("the release does not contain a %s deployment bundle", target)
}

func failed(name string, err error) phase {
	return phase{Name: name, State: "failed", Detail: err.Error()}
}

func pass(name, detail string) phase {
	return phase{Name: name, State: "passed", Detail: detail}
}
