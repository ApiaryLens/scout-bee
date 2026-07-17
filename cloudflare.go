package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type cloudflareAdapter struct {
	executor         *executor
	healthAttempts   int
	healthRetryDelay time.Duration
}

func (a *cloudflareAdapter) preflight(ctx context.Context, input request) ([]phase, error) {
	if err := a.executor.runner.Find("wrangler"); err != nil {
		err = errors.New("Wrangler is required; install the pinned supported release from Cloudflare, then retry")
		return []phase{failed("Find Cloudflare deployment tool", err)}, err
	}
	phases := []phase{pass("Find Cloudflare deployment tool", "Found the Cloudflare deployment tool.")}
	token := input.Secrets["cloudflareApiToken"]
	if token == "" {
		if input.Mode == "dry-run" {
			return append(phases, pass("Review guarded cost profile", "The plan uses family-free-guarded limits. Account quota checks will run when a token is supplied.")), nil
		}
		err := errors.New("a Cloudflare API token is required only while applying the plan")
		return append(phases, failed("Verify Cloudflare account access", err)), err
	}
	_, err := a.executor.runner.Run(ctx, command{
		Executable: "wrangler", Args: []string{"whoami", "--json"},
		Environment: map[string]string{"CLOUDFLARE_API_TOKEN": token},
	}, input.Secrets)
	if err != nil {
		return append(phases, failed("Verify Cloudflare account access", err)), err
	}
	phases = append(phases,
		pass("Verify Cloudflare account access", "The runtime token is valid and was not written to disk."),
		pass("Review guarded cost profile", "The deployment uses named family resources and does not enable paid platform features."),
	)
	if input.Plan.Operation == "install" {
		existing, inspectErr := a.existingWorkerSecretNames(ctx, input.Plan.Cloudflare.WorkerName, map[string]string{"CLOUDFLARE_API_TOKEN": token}, input.Secrets)
		if inspectErr != nil {
			return append(phases, failed("Inspect retained installation protection", inspectErr)), inspectErr
		}
		if !existing["AUTH_ROOT_SECRET"] && len(input.Secrets["bootstrapToken"]) < 16 {
			err := errors.New("an owner setup code of at least 16 characters is required only while installing")
			return append(phases, failed("Verify one-time owner setup protection", err)), err
		}
		if existing["AUTH_ROOT_SECRET"] {
			phases = append(phases, pass("Inspect retained installation protection", "The dormant installation retains its authentication root and does not require a new owner setup code."))
		}
	}
	return phases, nil
}

func (a *cloudflareAdapter) apply(ctx context.Context, input request, manifest releaseManifest) ([]phase, error) {
	switch input.Plan.Operation {
	case "install", "update", "repair", "rollback":
		return a.deploy(ctx, input, manifest)
	case "backup", "export", "restore":
		return a.maintain(ctx, input, manifest)
	case "uninstall":
		return a.uninstall(ctx, input)
	default:
		err := fmt.Errorf("unsupported Cloudflare operation %s", input.Plan.Operation)
		return []phase{failed("Apply Cloudflare operation", err)}, err
	}
}

func (a *cloudflareAdapter) maintain(ctx context.Context, input request, manifest releaseManifest) ([]phase, error) {
	cf := input.Plan.Cloudflare
	if cf.CustomDomain == "" {
		err := errors.New("backup, export, and restore require the deployment's verified HTTPS address in the plan")
		return []phase{failed("Locate protected maintenance service", err)}, err
	}
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return []phase{failed("Create one-time maintenance authorization", err)}, err
	}
	operatorToken := base64.RawURLEncoding.EncodeToString(tokenBytes)
	environment := map[string]string{"CLOUDFLARE_API_TOKEN": input.Secrets["cloudflareApiToken"]}
	runtimeSecrets := map[string]string{"cloudflareApiToken": input.Secrets["cloudflareApiToken"], "operatorToken": operatorToken}
	secretPayload, _ := json.Marshal(map[string]string{"SCOUT_OPERATOR_TOKEN": operatorToken})
	secretCommand := command{Executable: "wrangler", Args: []string{"secret", "bulk", "--name", cf.WorkerName}, Stdin: secretPayload, Environment: environment}
	if _, err := a.executor.runner.Run(ctx, secretCommand, runtimeSecrets); err != nil {
		return []phase{failed("Create one-time maintenance authorization", err)}, err
	}
	phases := []phase{pass("Create one-time maintenance authorization", "A temporary random authorization was stored without entering the plan or logs.")}
	defer func() {
		_, _ = a.executor.runner.Run(context.Background(), command{Executable: "wrangler", Args: []string{"secret", "delete", "SCOUT_OPERATOR_TOKEN", "--name", cf.WorkerName}, Stdin: []byte("y\n"), Environment: environment}, runtimeSecrets)
	}()

	endpoint := strings.TrimSuffix(cf.CustomDomain, "/") + "/api/v1/operator/"
	if input.Plan.Operation == "restore" {
		path := input.Secrets["backupFilePath"]
		if path == "" {
			err := errors.New("select a verified ApiaryLens backup file before restoring")
			return append(phases, failed("Read verified backup archive", err)), err
		}
		archive, err := os.ReadFile(path)
		if err != nil {
			return append(phases, failed("Read verified backup archive", err)), err
		}
		if err = validateZip(archive); err != nil {
			return append(phases, failed("Read verified backup archive", err)), err
		}
		preRestoreResponse, err := a.operatorRequest(ctx, http.MethodGet, endpoint+"backup", operatorToken, nil)
		if err != nil {
			return append(phases, failed("Back up current deployment before restore", err)), err
		}
		currentArchive, readErr := io.ReadAll(io.LimitReader(preRestoreResponse.Body, 2<<30))
		preRestoreResponse.Body.Close()
		if preRestoreResponse.StatusCode != http.StatusOK || readErr != nil {
			if readErr != nil {
				err = readErr
			} else {
				err = fmt.Errorf("backup service returned HTTP %d", preRestoreResponse.StatusCode)
			}
			return append(phases, failed("Back up current deployment before restore", err)), err
		}
		if err = validateZip(currentArchive); err != nil {
			return append(phases, failed("Back up current deployment before restore", err)), err
		}
		recoveryPath := filepath.Join(filepath.Dir(path), "apiarylens-pre-restore-"+time.Now().UTC().Format("20060102T150405Z")+".zip")
		if err = os.WriteFile(recoveryPath, currentArchive, 0o600); err != nil {
			return append(phases, failed("Back up current deployment before restore", err)), err
		}
		phases = append(phases, pass("Back up current deployment before restore", recoveryPath))
		response, err := a.operatorRequest(ctx, http.MethodPost, endpoint+"restore", operatorToken, archive)
		if err != nil || response.StatusCode != http.StatusOK {
			if err == nil {
				response.Body.Close()
				err = fmt.Errorf("restore service returned HTTP %d", response.StatusCode)
			}
			return append(phases, failed("Restore records and private media", err)), err
		}
		response.Body.Close()
		phases = append(phases, pass("Restore records and private media", "The compatible database and private media archive was restored; prior sessions were revoked."))
		if err = a.verifyHealth(ctx, strings.TrimSuffix(cf.CustomDomain, "/")+"/health", manifest); err != nil {
			return append(phases, failed("Verify restored deployment health", err)), err
		}
		return append(phases, pass("Verify restored deployment health", "The restored service reports the expected release identity.")), nil
	}

	response, err := a.operatorRequest(ctx, http.MethodGet, endpoint+"backup", operatorToken, nil)
	if err != nil {
		return append(phases, failed("Create portable backup archive", err)), err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		err = fmt.Errorf("backup service returned HTTP %d", response.StatusCode)
		return append(phases, failed("Create portable backup archive", err)), err
	}
	archive, err := io.ReadAll(io.LimitReader(response.Body, 2<<30))
	if err != nil {
		return append(phases, failed("Create portable backup archive", err)), err
	}
	if err = validateZip(archive); err != nil {
		return append(phases, failed("Verify portable backup archive", err)), err
	}
	directory := input.Secrets["backupDestination"]
	if directory == "" {
		home, _ := os.UserHomeDir()
		directory = filepath.Join(home, "Downloads")
	}
	if err = os.MkdirAll(directory, 0o700); err != nil {
		return append(phases, failed("Save portable backup archive", err)), err
	}
	filename := fmt.Sprintf("apiarylens-%s-%s.zip", input.Plan.Operation, time.Now().UTC().Format("20060102T150405Z"))
	destination := filepath.Join(directory, filename)
	if err = os.WriteFile(destination, archive, 0o600); err != nil {
		return append(phases, failed("Save portable backup archive", err)), err
	}
	phases = append(phases,
		pass("Create portable backup archive", "Cloudflare records and private media were streamed through the protected deployment endpoint."),
		pass("Verify portable backup archive", "The resulting ZIP archive is readable and contains a manifest."),
		pass("Save portable backup archive", destination),
	)
	return phases, nil
}

func (a *cloudflareAdapter) operatorRequest(ctx context.Context, method, endpoint, token string, body []byte) (*http.Response, error) {
	// Cloudflare secret versions can take longer than a fixed deployment delay to
	// reach every edge. Keep the request bounded by the caller's context while
	// allowing up to one minute for the concealed operator route to become visible.
	const attempts = 120
	for attempt := 0; attempt < attempts; attempt++ {
		var reader io.Reader
		if body != nil {
			reader = bytes.NewReader(body)
		}
		request, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
		if err != nil {
			return nil, err
		}
		request.Header.Set("authorization", "Bearer "+token)
		if body != nil {
			request.Header.Set("content-type", "application/zip")
		}
		response, err := a.executor.client.Do(request)
		if err != nil || response.StatusCode != http.StatusNotFound || attempt == attempts-1 {
			return response, err
		}
		_, _ = io.Copy(io.Discard, response.Body)
		response.Body.Close()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
	return nil, errors.New("operator authorization did not become available")
}

func validateZip(raw []byte) error {
	reader, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return errors.New("the backup is not a readable ZIP archive")
	}
	for _, file := range reader.File {
		if file.Name == "manifest.json" {
			return nil
		}
	}
	return errors.New("the backup archive has no ApiaryLens manifest")
}

func (a *cloudflareAdapter) deploy(ctx context.Context, input request, manifest releaseManifest) ([]phase, error) {
	artifact, err := artifactFor(manifest, "cloudflare")
	if err != nil {
		return []phase{failed("Select verified Cloudflare bundle", err)}, err
	}
	temp, err := os.MkdirTemp("", "apiarylens-scout-cloudflare-")
	if err != nil {
		return []phase{failed("Prepare protected staging folder", err)}, err
	}
	defer os.RemoveAll(temp)
	bundle, err := a.executor.downloadArtifact(ctx, artifact, temp)
	if err != nil {
		return []phase{failed("Download and verify deployment bundle", err)}, err
	}
	phases := []phase{pass("Download and verify deployment bundle", "The immutable Cloudflare bundle matches the release manifest.")}
	root := filepath.Join(temp, "bundle")
	if err = os.Mkdir(root, 0o700); err == nil {
		err = extractTarGz(bundle, root)
	}
	if err != nil {
		return append(phases, failed("Stage deployment bundle", err)), err
	}
	phases = append(phases, pass("Stage deployment bundle", "The checked bundle was extracted without links or unsafe paths."))

	cf := input.Plan.Cloudflare
	workersDev := cf.CustomDomain == "" || isWorkersDevAddress(cf.CustomDomain)
	token := input.Secrets["cloudflareApiToken"]
	environment := map[string]string{"CLOUDFLARE_API_TOKEN": token}
	if input.Plan.Operation == "update" || input.Plan.Operation == "repair" || input.Plan.Operation == "rollback" {
		backupInput := input
		backupInput.Plan.Operation = "backup"
		backupPhases, backupErr := a.maintain(ctx, backupInput, manifest)
		phases = append(phases, backupPhases...)
		if backupErr != nil {
			return append(phases, failed("Require verified backup before update", backupErr)), backupErr
		}
		phases = append(phases, pass("Require verified backup before update", "A readable, versioned backup was saved before any migration or deployment change."))
	}
	databaseID, err := a.ensureD1(ctx, cf.D1DatabaseName, environment, input.Secrets)
	if err != nil {
		return append(phases, failed("Create or reuse records database", err)), err
	}
	phases = append(phases, pass("Create or reuse records database", "The exact named D1 database is ready."))
	if err = a.ensureR2(ctx, cf.R2BucketName, environment, input.Secrets); err != nil {
		return append(phases, failed("Create or reuse private media storage", err)), err
	}
	phases = append(phases, pass("Create or reuse private media storage", "The exact named private R2 bucket is ready."))

	configPath := filepath.Join(root, "wrangler.scout.json")
	config := map[string]any{
		"name": cf.WorkerName, "main": "worker/index.js", "compatibility_date": "2026-07-15",
		"compatibility_flags": []string{"nodejs_compat"}, "send_metrics": false,
		"account_id": cf.AccountReference, "workers_dev": workersDev,
		"observability": map[string]any{"enabled": false},
		"vars": map[string]string{
			"APIARYLENS_SOURCE_COMMIT":     manifest.SourceCommit,
			"APIARYLENS_BUILD_TIME":        manifest.BuildTime,
			"APIARYLENS_ARTIFACT_IDENTITY": "ApiaryLens@" + manifest.ProductVersion + "+" + shortCommit(manifest.SourceCommit),
		},
		"d1_databases": []map[string]string{{"binding": "DB", "database_name": cf.D1DatabaseName, "database_id": databaseID, "migrations_dir": "worker/migrations"}},
		"r2_buckets":   []map[string]string{{"binding": "MEDIA", "bucket_name": cf.R2BucketName}},
		"assets":       map[string]any{"directory": "web", "binding": "ASSETS", "not_found_handling": "single-page-application", "run_worker_first": []string{"/api/*", "/health"}},
	}
	if cf.CustomDomain != "" && !workersDev {
		parsed, _ := url.Parse(cf.CustomDomain)
		config["routes"] = []map[string]any{{"pattern": parsed.Hostname(), "custom_domain": true}}
	}
	rawConfig, _ := json.MarshalIndent(config, "", "  ")
	if err = os.WriteFile(configPath, append(rawConfig, '\n'), 0o600); err != nil {
		return append(phases, failed("Write ephemeral deployment configuration", err)), err
	}
	if _, err = a.executor.runner.Run(ctx, command{Executable: "wrangler", Args: []string{"d1", "migrations", "apply", cf.D1DatabaseName, "--remote", "--config", configPath}, Directory: root, Environment: environment}, input.Secrets); err != nil {
		return append(phases, failed("Apply compatible database migrations", err)), err
	}
	phases = append(phases, pass("Apply compatible database migrations", "Ordered D1 migrations completed."))

	runtimeSecrets := map[string]string{"cloudflareApiToken": token}
	deployArgs := []string{"deploy", "--config", configPath}
	if input.Plan.Operation == "install" {
		existing, inspectErr := a.existingWorkerSecretNames(ctx, cf.WorkerName, environment, input.Secrets)
		if inspectErr != nil {
			return append(phases, failed("Inspect retained installation protection", inspectErr)), inspectErr
		}
		if existing["AUTH_ROOT_SECRET"] {
			phases = append(phases, pass("Preserve retained authentication root", "The reinstall preserves the existing authentication root so retained accounts and sessions remain usable."))
		} else {
			bootstrap := input.Secrets["bootstrapToken"]
			if len(bootstrap) < 16 {
				err = errors.New("an owner setup code of at least 16 characters is required for a fresh installation")
				return append(phases, failed("Prepare one-time owner setup protection", err)), err
			}
			authRootBytes := make([]byte, 48)
			if _, err = rand.Read(authRootBytes); err != nil {
				return append(phases, failed("Prepare authentication root secret", err)), err
			}
			authRoot := base64.RawURLEncoding.EncodeToString(authRootBytes)
			runtimeSecrets["bootstrapToken"] = bootstrap
			runtimeSecrets["authRootSecret"] = authRoot
			bootstrapPayload, _ := json.Marshal(map[string]string{
				"BOOTSTRAP_TOKEN":  bootstrap,
				"AUTH_ROOT_SECRET": authRoot,
			})
			secretsPath := filepath.Join(temp, "runtime-secrets.json")
			if err = os.WriteFile(secretsPath, bootstrapPayload, 0o600); err != nil {
				return append(phases, failed("Prepare one-time owner setup protection", err)), err
			}
			deployArgs = append(deployArgs, "--secrets-file", secretsPath)
			phases = append(phases,
				pass("Prepare one-time owner setup protection", "Your runtime-only owner setup code will be installed atomically with the application and was not logged."),
				pass("Prepare authentication root secret", "A random durable root secret will domain-separate password and session hashing without entering the plan or logs."),
			)
		}
	}

	output, err := a.executor.runner.Run(ctx, command{Executable: "wrangler", Args: deployArgs, Directory: root, Environment: environment}, runtimeSecrets)
	if err != nil {
		return append(phases, failed("Deploy Worker and PWA assets", err)), err
	}
	phases = append(phases, pass("Deploy Worker and PWA assets", "The exact release bundle was deployed."))
	address := cf.CustomDomain
	if address == "" {
		address = firstWorkersDevURL(output)
	}
	if address == "" {
		return append(phases, failed("Verify deployment health", errors.New("Wrangler did not report a deployment address"))), errors.New("deployment address was not reported")
	}
	if err = a.verifyHealth(ctx, strings.TrimSuffix(address, "/")+"/health", manifest); err != nil {
		return append(phases, failed("Verify deployment health", err)), err
	}
	phases = append(phases, pass("Verify deployment health", "The deployed service reports the expected product and release version."))
	return phases, nil
}

func isWorkersDevAddress(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && strings.HasSuffix(strings.ToLower(parsed.Hostname()), ".workers.dev")
}

func (a *cloudflareAdapter) uninstall(ctx context.Context, input request) ([]phase, error) {
	cf := input.Plan.Cloudflare
	if !input.Plan.KeepDataOnUninstall {
		err := errors.New("Cloudflare data deletion requires a separate typed confirmation; no service or data was changed")
		return []phase{failed("Preserve recoverable Cloudflare data", err)}, err
	}
	token := input.Secrets["cloudflareApiToken"]
	temp, err := os.MkdirTemp("", "apiarylens-scout-disabled-")
	if err != nil {
		return []phase{failed("Prepare disabled Cloudflare service", err)}, err
	}
	defer os.RemoveAll(temp)
	workerPath := filepath.Join(temp, "disabled.js")
	configPath := filepath.Join(temp, "wrangler.disabled.json")
	if err = os.WriteFile(workerPath, []byte("export default {fetch(){return new Response('ApiaryLens is uninstalled',{status:410})}};\n"), 0o600); err != nil {
		return []phase{failed("Prepare disabled Cloudflare service", err)}, err
	}
	config := map[string]any{
		"name": cf.WorkerName, "main": "disabled.js", "compatibility_date": "2026-07-15",
		"account_id": cf.AccountReference, "workers_dev": false, "preview_urls": false,
		"routes": []any{}, "send_metrics": false, "observability": map[string]any{"enabled": false},
	}
	raw, _ := json.MarshalIndent(config, "", "  ")
	if err = os.WriteFile(configPath, append(raw, '\n'), 0o600); err != nil {
		return []phase{failed("Prepare disabled Cloudflare service", err)}, err
	}
	_, err = a.executor.runner.Run(ctx, command{Executable: "wrangler", Args: []string{"deploy", "--config", configPath}, Environment: map[string]string{"CLOUDFLARE_API_TOKEN": token}}, input.Secrets)
	if err != nil {
		return []phase{failed("Disable Cloudflare application exposure", err)}, err
	}
	return []phase{pass("Disable Cloudflare application exposure", "Public triggers were removed while the dormant service retained its authentication secret, D1 records, and R2 media for a recoverable reinstall.")}, nil
}

func (a *cloudflareAdapter) ensureD1(ctx context.Context, name string, environment, secrets map[string]string) (string, error) {
	list := func() (string, error) {
		out, err := a.executor.runner.Run(ctx, command{Executable: "wrangler", Args: []string{"d1", "list", "--json"}, Environment: environment}, secrets)
		if err != nil {
			return "", err
		}
		var rows []struct {
			Name string `json:"name"`
			UUID string `json:"uuid"`
		}
		if err := json.Unmarshal([]byte(out), &rows); err != nil {
			return "", errors.New("Wrangler returned an unreadable D1 resource list")
		}
		for _, row := range rows {
			if row.Name == name {
				return row.UUID, nil
			}
		}
		return "", nil
	}
	id, err := list()
	if err != nil || id != "" {
		return id, err
	}
	if _, err = a.executor.runner.Run(ctx, command{Executable: "wrangler", Args: []string{"d1", "create", name}, Environment: environment}, secrets); err != nil {
		return "", err
	}
	id, err = list()
	if err != nil {
		return "", err
	}
	if id == "" {
		return "", errors.New("D1 database creation completed but the resource could not be found")
	}
	return id, nil
}

func (a *cloudflareAdapter) ensureR2(ctx context.Context, name string, environment, secrets map[string]string) error {
	out, err := a.executor.runner.Run(ctx, command{Executable: "wrangler", Args: []string{"r2", "bucket", "list"}, Environment: environment}, secrets)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(out, "\n") {
		label, value, found := strings.Cut(strings.TrimSpace(line), ":")
		if found && label == "name" && strings.TrimSpace(value) == name {
			return nil
		}
	}
	_, err = a.executor.runner.Run(ctx, command{Executable: "wrangler", Args: []string{"r2", "bucket", "create", name}, Environment: environment}, secrets)
	return err
}

func (a *cloudflareAdapter) existingWorkerSecretNames(ctx context.Context, name string, environment, secrets map[string]string) (map[string]bool, error) {
	out, err := a.executor.runner.Run(ctx, command{
		Executable: "wrangler", Args: []string{"secret", "list", "--name", name, "--format", "json"}, Environment: environment,
	}, secrets)
	if err != nil {
		lower := strings.ToLower(out)
		if strings.Contains(lower, strings.ToLower(name)) && strings.Contains(lower, "not found") {
			return map[string]bool{}, nil
		}
		return nil, err
	}
	var rows []struct {
		Name string `json:"name"`
	}
	if err = json.Unmarshal([]byte(out), &rows); err != nil {
		return nil, errors.New("Wrangler returned an unreadable Worker secret list")
	}
	result := make(map[string]bool, len(rows))
	for _, row := range rows {
		result[row.Name] = true
	}
	return result, nil
}

func (a *cloudflareAdapter) verifyHealth(ctx context.Context, address string, manifest releaseManifest) error {
	attempts := a.healthAttempts
	if attempts <= 0 {
		attempts = 600
	}
	delay := a.healthRetryDelay
	if delay <= 0 {
		delay = 500 * time.Millisecond
	}
	var lastErr error
	for attempt := 0; attempt < attempts; attempt++ {
		if lastErr = a.checkHealth(ctx, address, manifest); lastErr == nil {
			return nil
		}
		if attempt == attempts-1 {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
	}
	return fmt.Errorf("deployment health did not converge: %w", lastErr)
}

func (a *cloudflareAdapter) checkHealth(ctx context.Context, address string, manifest releaseManifest) error {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return err
	}
	response, err := a.executor.client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("health endpoint returned HTTP %d", response.StatusCode)
	}
	var result struct {
		Status, Product, Version string
		Build                    struct {
			SourceCommit, BuildTime, ArtifactIdentity string
		}
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return err
	}
	if result.Status != "ok" || result.Product != "ApiaryLens" || result.Version != manifest.ProductVersion {
		return errors.New("health identity does not match the requested release")
	}
	if manifest.SourceCommit != "" && (result.Build.SourceCommit != manifest.SourceCommit || result.Build.BuildTime != manifest.BuildTime || result.Build.ArtifactIdentity != "ApiaryLens@"+manifest.ProductVersion+"+"+shortCommit(manifest.SourceCommit)) {
		return errors.New("health build identity does not match the release manifest")
	}
	return nil
}

func shortCommit(value string) string {
	if len(value) <= 7 {
		return value
	}
	return value[:7]
}

var httpsURLPattern = regexp.MustCompile(`https://[^\s]+`)

func firstWorkersDevURL(value string) string {
	for _, match := range httpsURLPattern.FindAllString(value, -1) {
		candidate := strings.TrimRight(match, ".,;)")
		if isWorkersDevAddress(candidate) {
			return candidate
		}
	}
	return ""
}
