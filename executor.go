package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
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

// GitHub Releases on the official product repository is the live distribution
// point for ApiaryLens Preview 1. apiarylens.org remains the declared future
// release home; its URLs are kept only where nothing has shipped yet so the
// flow fails closed instead of silently resolving elsewhere.
const (
	officialProductRepositoryURL = "https://github.com/ApiaryLens/apiarylens"
	officialAttestationURL       = "https://api.github.com/repos/ApiaryLens/apiarylens/attestations"
)

var officialReleaseDownloadBase = officialProductRepositoryURL + "/releases/download/"

var officialReleaseManifestURLs = map[string]string{
	// The newest published stable release. GitHub resolves this only when a
	// non-prerelease release exists, so it fails closed until stable ships;
	// the manifest identity checks below still require channel "stable".
	"stable": officialProductRepositoryURL + "/releases/latest/download/release-manifest.json",
	// No release candidate has been published; this fails closed today.
	"release-candidate": "https://apiarylens.org/releases/release-candidate/manifest.json",
	// Preview is pinned to the exact published build this Scout supports.
	"preview": officialReleaseDownloadBase + "v0.1.0-preview.6/release-manifest.json",
}

// releaseRedirectHosts are the only hosts a GitHub release download may pass
// through: github.com release asset URLs answer with a redirect to GitHub's
// dedicated release storage.
var releaseRedirectHosts = map[string]bool{
	"github.com":                           true,
	"objects.githubusercontent.com":        true,
	"release-assets.githubusercontent.com": true,
}

// releaseRedirectPolicy refuses every redirect except the HTTPS redirect chain
// GitHub uses to serve release assets, and only when the request started at
// github.com. Every downloaded artifact byte is still verified against the
// pinned SHA-256 and declared size, so the transport cannot substitute content.
func releaseRedirectPolicy(req *http.Request, via []*http.Request) error {
	if len(via) == 0 || via[0].URL.Hostname() != "github.com" {
		return errors.New("release downloads may not redirect")
	}
	if len(via) > 3 {
		return errors.New("release downloads may not redirect more than three times")
	}
	if req.URL.Scheme != "https" || req.URL.User != nil || !releaseRedirectHosts[req.URL.Hostname()] {
		return errors.New("release downloads may only redirect to GitHub release storage")
	}
	return nil
}

// wsl and sh exist for the local-machine trial target: the same released
// lifecycle script Scout streams to remote hosts over SSH is streamed to a
// local POSIX shell (WSL2 on Windows, sh elsewhere). Scout never executes
// artifact bytes directly; the script drives Docker Compose.
var allowedExecutables = map[string]bool{
	"wrangler": true, "ssh": true, "scp": true, "ssh-keyscan": true,
	"wsl": true, "sh": true,
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
	if err != nil {
		jsonResponse(w, http.StatusBadGateway, map[string]string{"message": "The official release identity is unavailable"})
		return
	}
	defer response.Body.Close()
	if channel == "stable" && response.StatusCode == http.StatusNotFound {
		// The empty-stable edge case (owner UAT 2026-07-19): no stable
		// ApiaryLens release has been published, so the guide must say so
		// plainly and offer the preview opt-in instead of dead-ending.
		jsonResponse(w, http.StatusNotFound, map[string]any{
			"message":      "ApiaryLens has not shipped a stable release yet; previews are currently the only channel",
			"channelEmpty": true,
		})
		return
	}
	if response.StatusCode != http.StatusOK {
		jsonResponse(w, http.StatusBadGateway, map[string]string{"message": "The official release identity is unavailable"})
		return
	}
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
	cmd.Env = mergedEnvironment(os.Environ(), spec.Environment)
	out, runErr := cmd.CombinedOutput()
	clean := redact(string(out), secrets)
	if runErr != nil {
		return clean, fmt.Errorf("%s failed: %w", spec.Executable, runErr)
	}
	return clean, nil
}

func mergedEnvironment(base []string, overrides map[string]string) []string {
	if len(overrides) == 0 {
		return base
	}
	result := make([]string, 0, len(base)+len(overrides))
	for _, entry := range base {
		key, _, found := strings.Cut(entry, "=")
		if !found {
			continue
		}
		replaced := false
		for override := range overrides {
			if strings.EqualFold(key, override) {
				replaced = true
				break
			}
		}
		if !replaced {
			result = append(result, entry)
		}
	}
	for key, value := range overrides {
		result = append(result, key+"="+value)
	}
	return result
}

type executor struct {
	runner                commandRunner
	client                *http.Client
	allowLoopback         bool
	store                 *operationStore
	cacheDirectory        string
	attestationURL        string
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
		attestationURL: officialAttestationURL,
		client:         &http.Client{Timeout: 30 * time.Second, CheckRedirect: releaseRedirectPolicy},
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
	_ = e.store.save(operationState{
		Plan: input.Plan, Mode: input.Mode, Status: status, Phases: phases,
		StartedAt: started, FinishedAt: &finished,
		Verification: buildReleaseVerification(input.Plan.Release, result.Manifest),
	})
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
	} else if input.Plan.Target == "compose-local" {
		adapter = &localComposeAdapter{executor: e}
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
	if manifest.Product != "ApiaryLens" || manifest.ProductVersion != expected.Version || manifest.Channel != expected.Channel || manifest.Contracts.DeploymentPlan != 1 || !compatibleProductVersion(manifest.ProductVersion) {
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

// downloadVerifiedArtifact downloads through the URL declared in the release
// manifest first and falls back to the official GitHub release asset with the
// same file name when the declared distribution point is unavailable
// (apiarylens.org does not serve releases yet). Both paths verify every byte
// against the SHA-256 and size pinned in the already-verified release
// manifest, so neither source can substitute content.
func (e *executor) downloadVerifiedArtifact(ctx context.Context, manifest releaseManifest, artifact manifestArtifact, directory string) (string, error) {
	path, primaryErr := e.downloadArtifact(ctx, artifact, directory)
	if primaryErr == nil {
		return path, nil
	}
	fallback := artifact
	fallback.URL = officialReleaseDownloadBase + "v" + url.PathEscape(manifest.ProductVersion) + "/" + url.PathEscape(artifact.Name)
	if fallback.URL == artifact.URL || !safeHTTPSURL(fallback.URL) {
		return "", primaryErr
	}
	path, fallbackErr := e.downloadArtifact(ctx, fallback, directory)
	if fallbackErr != nil {
		return "", errors.Join(primaryErr, fallbackErr)
	}
	return path, nil
}

// attestationPAE is the DSSE pre-authentication encoding the signature covers.
func attestationPAE(payloadType string, payload []byte) []byte {
	return fmt.Appendf(nil, "DSSEv1 %d %s %d %s", len(payloadType), payloadType, len(payload), payload)
}

type attestationStatement struct {
	Type          string `json:"_type"`
	PredicateType string `json:"predicateType"`
	Subject       []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
	Predicate struct {
		BuildDefinition struct {
			ExternalParameters struct {
				Workflow struct {
					Repository string `json:"repository"`
					Path       string `json:"path"`
				} `json:"workflow"`
			} `json:"externalParameters"`
		} `json:"buildDefinition"`
	} `json:"predicate"`
}

// verifyArtifactAttestation fails closed unless GitHub's repository-scoped
// attestation endpoint returns a provenance statement that (1) carries a DSSE
// signature that cryptographically verifies against the ECDSA public key of
// the Sigstore certificate embedded in the bundle, (2) names the official
// ApiaryLens release workflow as the certificate's signing identity, and
// (3) has a subject whose name and SHA-256 match the verified artifact.
// Deliberately out of scope for this dependency-free executor: verifying the
// certificate chain to the Fulcio root and the transparency-log inclusion
// proof (the leaf certificate is minutes-lived, so wall-clock validity cannot
// be checked at install time either). Those checks remain available to
// operators through `gh attestation verify`.
func (e *executor) verifyArtifactAttestation(ctx context.Context, artifact manifestArtifact) (string, error) {
	base := e.attestationURL
	if base == "" {
		base = officialAttestationURL
	}
	requestURL := strings.TrimSuffix(base, "/") + "/sha256:" + strings.ToLower(artifact.Sha256)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	response, err := e.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("could not reach the GitHub attestation service: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound {
		return "", fmt.Errorf("GitHub holds no build attestation for artifact %q; refusing to continue", artifact.Name)
	}
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("the GitHub attestation service returned HTTP %d", response.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, 4<<20))
	if err != nil {
		return "", err
	}
	var payload struct {
		Attestations []struct {
			Bundle struct {
				VerificationMaterial struct {
					Certificate struct {
						RawBytes string `json:"rawBytes"`
					} `json:"certificate"`
				} `json:"verificationMaterial"`
				DSSEEnvelope struct {
					PayloadType string `json:"payloadType"`
					Payload     string `json:"payload"`
					Signatures  []struct {
						Sig string `json:"sig"`
					} `json:"signatures"`
				} `json:"dsseEnvelope"`
			} `json:"bundle"`
		} `json:"attestations"`
	}
	if err = json.Unmarshal(raw, &payload); err != nil {
		return "", errors.New("the GitHub attestation response is unreadable")
	}
	for _, attestation := range payload.Attestations {
		envelope := attestation.Bundle.DSSEEnvelope
		if envelope.PayloadType != "application/vnd.in-toto+json" {
			continue
		}
		decoded, decodeErr := base64.StdEncoding.DecodeString(envelope.Payload)
		if decodeErr != nil {
			continue
		}
		certDER, certErr := base64.StdEncoding.DecodeString(attestation.Bundle.VerificationMaterial.Certificate.RawBytes)
		if certErr != nil || len(certDER) == 0 {
			continue
		}
		certificate, parseErr := x509.ParseCertificate(certDER)
		if parseErr != nil {
			continue
		}
		publicKey, isECDSA := certificate.PublicKey.(*ecdsa.PublicKey)
		if !isECDSA {
			continue
		}
		digest := sha256.Sum256(attestationPAE(envelope.PayloadType, decoded))
		signatureVerified := false
		for _, signature := range envelope.Signatures {
			signatureBytes, signatureErr := base64.StdEncoding.DecodeString(signature.Sig)
			if signatureErr == nil && ecdsa.VerifyASN1(publicKey, digest[:], signatureBytes) {
				signatureVerified = true
				break
			}
		}
		if !signatureVerified {
			continue
		}
		signingIdentityVerified := false
		for _, identity := range certificate.URIs {
			if strings.HasPrefix(identity.String(), officialProductRepositoryURL+"/") {
				signingIdentityVerified = true
				break
			}
		}
		if !signingIdentityVerified {
			continue
		}
		var statement attestationStatement
		if json.Unmarshal(decoded, &statement) != nil {
			continue
		}
		if statement.Type != "https://in-toto.io/Statement/v1" ||
			statement.PredicateType != "https://slsa.dev/provenance/v1" ||
			statement.Predicate.BuildDefinition.ExternalParameters.Workflow.Repository != officialProductRepositoryURL {
			continue
		}
		for _, subject := range statement.Subject {
			if subject.Name == artifact.Name && strings.EqualFold(subject.Digest["sha256"], artifact.Sha256) {
				return "A Sigstore-signed provenance attestation from " + officialProductRepositoryURL +
					" covers this exact file name and SHA-256. Scout verified the DSSE signature against the embedded certificate and its GitHub workflow signing identity; certificate-chain and transparency-log verification remain available through `gh attestation verify`.", nil
			}
		}
	}
	return "", fmt.Errorf("no signed GitHub attestation binds artifact %q and its SHA-256 to the official ApiaryLens repository build", artifact.Name)
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
