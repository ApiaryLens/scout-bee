package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"
)

// Scout and ApiaryLens are independently versioned. Release builds override
// scoutVersion from VERSION with -ldflags; supportedProductVersion identifies the
// exact compatibility baseline consumed by this transitional executor.
var scoutVersion = "0.1.0-preview.4"

type release struct {
	Version        string `json:"version"`
	Channel        string `json:"channel"`
	ManifestURL    string `json:"manifestUrl"`
	ManifestSha256 string `json:"manifestSha256"`
}

type cloudflare struct {
	AccountReference string `json:"accountReference"`
	WorkerName       string `json:"workerName"`
	D1DatabaseName   string `json:"d1DatabaseName"`
	R2BucketName     string `json:"r2BucketName"`
	CustomDomain     string `json:"customDomain,omitempty"`
	CostProfile      string `json:"costProfile"`
	// IncludeWebFrontend is a pointer so plans created before this option
	// continue to deploy the PWA. An explicit false selects an API-only
	// deployment without changing the secret-free plan contract.
	IncludeWebFrontend *bool `json:"includeWebFrontend,omitempty"`
}

type compose struct {
	Host               string `json:"host"`
	Port               int    `json:"port"`
	User               string `json:"user"`
	TargetDirectory    string `json:"targetDirectory"`
	ProjectName        string `json:"projectName"`
	PublicURL          string `json:"publicUrl"`
	SSHHostKeySha256   string `json:"sshHostKeySha256"`
	BackupRetention    int    `json:"backupRetention"`
	IncludeWebFrontend *bool  `json:"includeWebFrontend,omitempty"`
}

func webFrontendEnabled(value *bool) bool {
	return value == nil || *value
}

type windowsClient struct {
	Architecture string `json:"architecture"`
}

// localCompose is the owner-directed "on this local machine" trial target
// (2026-07-19): the released Compose bundle run on this computer through
// WSL2/Docker Desktop on Windows or Docker on Linux. It serves plain HTTP on
// localhost only and never presents connected/sync options (design v2 §1c).
type localCompose struct {
	InstallDirectory string `json:"installDirectory"`
	ProjectName      string `json:"projectName"`
	HTTPPort         int    `json:"httpPort"`
}

type plan struct {
	SchemaVersion       int            `json:"schemaVersion"`
	PlanID              string         `json:"planId"`
	CreatedAt           string         `json:"createdAt"`
	Release             release        `json:"release"`
	Operation           string         `json:"operation"`
	KeepDataOnUninstall bool           `json:"keepDataOnUninstall"`
	Target              string         `json:"target"`
	Cloudflare          *cloudflare    `json:"cloudflare,omitempty"`
	Compose             *compose       `json:"compose,omitempty"`
	LocalCompose        *localCompose  `json:"localCompose,omitempty"`
	WindowsClient       *windowsClient `json:"windowsClient,omitempty"`
}

type request struct {
	Plan    plan              `json:"plan"`
	Mode    string            `json:"mode"`
	Secrets map[string]string `json:"secrets,omitempty"`
}

type phase struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
}

type releaseManifest struct {
	Product        string             `json:"product"`
	ProductVersion string             `json:"productVersion"`
	Channel        string             `json:"channel"`
	SourceCommit   string             `json:"sourceCommit"`
	BuildTime      string             `json:"buildTime"`
	Contracts      manifestContracts  `json:"contracts"`
	Artifacts      []manifestArtifact `json:"artifacts"`
}

type manifestContracts struct {
	APIVersion        string `json:"api"`
	Sync              int    `json:"sync"`
	DatabaseMigration string `json:"databaseMigration"`
	DeploymentPlan    int    `json:"deploymentPlan"`
}

type manifestArtifact struct {
	Name   string `json:"name"`
	Kind   string `json:"kind"`
	Target string `json:"target"`
	URL    string `json:"url"`
	Sha256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type windowsPackageManifest struct {
	SchemaVersion  int                      `json:"schemaVersion"`
	Product        string                   `json:"product"`
	ProductVersion string                   `json:"productVersion"`
	Architecture   string                   `json:"architecture"`
	PackageKind    string                   `json:"packageKind"`
	SourceCommit   string                   `json:"sourceCommit"`
	Signed         bool                     `json:"signed"`
	Signature      windowsPackageSignature  `json:"signature"`
	Artifacts      []windowsPackageArtifact `json:"artifacts"`
}

type windowsPackageSignature struct {
	Publisher  string `json:"publisher"`
	Thumbprint string `json:"thumbprint"`
}

type windowsPackageArtifact struct {
	Name   string `json:"name"`
	Sha256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type windowsConnectionProfile struct {
	SchemaVersion      int                  `json:"schemaVersion"`
	ProfileID          string               `json:"profileId"`
	DisplayName        string               `json:"displayName"`
	Mode               string               `json:"mode"`
	ClientKind         string               `json:"clientKind"`
	BackendURL         string               `json:"backendUrl"`
	DeploymentProfile  string               `json:"deploymentProfile"`
	ProvisioningSource string               `json:"provisioningSource"`
	CreatedAt          string               `json:"createdAt"`
	Compatibility      profileCompatibility `json:"compatibility"`
}

type profileCompatibility struct {
	ProductVersion    string `json:"productVersion"`
	APIContract       string `json:"apiContract"`
	SyncContract      int    `json:"syncContract"`
	DatabaseMigration string `json:"databaseMigration"`
}

func buildWindowsConnectionProfile(p plan, manifest releaseManifest, backendURL string, createdAt time.Time) *windowsConnectionProfile {
	if !safeHTTPSURL(backendURL) || (p.Operation != "install" && p.Operation != "update" && p.Operation != "repair" && p.Operation != "rollback") {
		return nil
	}
	displayName := "ApiaryLens deployment"
	deploymentProfile := "compose"
	if p.Target == "cloudflare" {
		displayName = p.Cloudflare.WorkerName
		deploymentProfile = "cloudflare"
	} else if p.Compose != nil {
		displayName = p.Compose.ProjectName
	}
	return &windowsConnectionProfile{
		SchemaVersion: 1, ProfileID: p.PlanID, DisplayName: displayName,
		Mode: "connected", ClientKind: "windows", BackendURL: strings.TrimSuffix(backendURL, "/"),
		DeploymentProfile: deploymentProfile, ProvisioningSource: "scout", CreatedAt: createdAt.UTC().Format(time.RFC3339Nano),
		Compatibility: profileCompatibility{
			ProductVersion: manifest.ProductVersion, APIContract: manifest.Contracts.APIVersion,
			SyncContract: manifest.Contracts.Sync, DatabaseMigration: manifest.Contracts.DatabaseMigration,
		},
	}
}

var (
	resourceName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{2,62}$`)
	accountID    = regexp.MustCompile(`^[0-9a-fA-F]{32}$`)
	planID       = regexp.MustCompile(`^[0-9a-fA-F-]{36}$`)
	remotePath   = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)
	sshName      = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

func validate(p plan) error {
	if p.SchemaVersion != 1 {
		return errors.New("unsupported deployment plan version")
	}
	if !planID.MatchString(p.PlanID) || p.Release.Version == "" || !validSha256(p.Release.ManifestSha256) {
		return errors.New("the release identity is incomplete")
	}
	if parsed, err := time.Parse(time.RFC3339, p.CreatedAt); err != nil || time.Since(parsed) > 24*time.Hour || time.Until(parsed) > 5*time.Minute {
		return errors.New("the deployment plan creation time is invalid or stale")
	}
	if !safeHTTPSURL(p.Release.ManifestURL) {
		return errors.New("the release manifest must use HTTPS")
	}
	if p.Release.Channel != "preview" && p.Release.Channel != "release-candidate" && p.Release.Channel != "stable" {
		return errors.New("only preview, release-candidate, or stable releases may be applied")
	}
	allowedOperations := map[string]bool{"install": true, "update": true, "repair": true, "rollback": true, "backup": true, "restore": true, "export": true, "uninstall": true}
	if !allowedOperations[p.Operation] {
		return errors.New("the requested deployment operation is unsupported")
	}
	raw, _ := json.Marshal(p)
	lower := strings.ToLower(string(raw))
	for _, word := range []string{"password", "apitoken", "privatekey", "secret"} {
		if strings.Contains(lower, word) {
			return errors.New("secret-looking fields are not allowed in a deployment plan")
		}
	}
	switch p.Target {
	case "cloudflare":
		if p.Cloudflare == nil || p.Compose != nil || p.LocalCompose != nil || p.WindowsClient != nil {
			return errors.New("exactly one Cloudflare target is required")
		}
		if !accountID.MatchString(p.Cloudflare.AccountReference) || !resourceName.MatchString(p.Cloudflare.WorkerName) || !strings.HasPrefix(p.Cloudflare.WorkerName, "apiarylens-") ||
			!resourceName.MatchString(p.Cloudflare.D1DatabaseName) || !resourceName.MatchString(p.Cloudflare.R2BucketName) {
			return errors.New("a 32-character Cloudflare account ID and safe lowercase resource names are required; the Worker must begin with apiarylens-")
		}
		if p.Cloudflare.CostProfile != "family-free-guarded" {
			return errors.New("the Cloudflare family profile requires guarded cost limits")
		}
		if p.Cloudflare.CustomDomain != "" && !safeHTTPSURL(p.Cloudflare.CustomDomain) {
			return errors.New("the Cloudflare custom domain must be a complete HTTPS address")
		}
	case "compose-ssh":
		if p.Compose == nil || p.Cloudflare != nil || p.LocalCompose != nil || p.WindowsClient != nil {
			return errors.New("exactly one Compose target is required")
		}
		if !sshName.MatchString(p.Compose.Host) || !sshName.MatchString(p.Compose.User) || !resourceName.MatchString(p.Compose.ProjectName) {
			return errors.New("the SSH host, user, or project name contains unsupported characters")
		}
		if p.Compose.Port < 1 || p.Compose.Port > 65535 ||
			!remotePath.MatchString(p.Compose.TargetDirectory) || strings.Contains(p.Compose.TargetDirectory, "..") ||
			p.Compose.TargetDirectory == "/" || path.Clean(p.Compose.TargetDirectory) != p.Compose.TargetDirectory {
			return errors.New("the remote port or install folder is unsafe")
		}
		if !composeHTTPSURL(p.Compose.PublicURL) {
			return errors.New("a network Compose deployment requires HTTPS on a resolvable hostname, not a raw IP address")
		}
		if !strings.HasPrefix(p.Compose.SSHHostKeySha256, "SHA256:") {
			return errors.New("a verified SSH host key is required")
		}
	case "compose-local":
		if p.LocalCompose == nil || p.Cloudflare != nil || p.Compose != nil || p.WindowsClient != nil {
			return errors.New("exactly one local trial target is required")
		}
		if !resourceName.MatchString(p.LocalCompose.ProjectName) {
			return errors.New("the local trial project name contains unsupported characters")
		}
		if !remotePath.MatchString(p.LocalCompose.InstallDirectory) || strings.Contains(p.LocalCompose.InstallDirectory, "..") ||
			p.LocalCompose.InstallDirectory == "/" || path.Clean(p.LocalCompose.InstallDirectory) != p.LocalCompose.InstallDirectory {
			return errors.New("the local trial install folder is unsafe")
		}
		if p.LocalCompose.HTTPPort < 1 || p.LocalCompose.HTTPPort > 65535 {
			return errors.New("the local trial HTTP port is invalid")
		}
	case "windows-client":
		if !windowsClientEnabled() {
			return errors.New("the Windows client target is disabled in this build; set SCOUT_BEE_ENABLE_WINDOWS_CLIENT=1 to enable it explicitly")
		}
		if p.WindowsClient == nil || p.Cloudflare != nil || p.Compose != nil || p.LocalCompose != nil {
			return errors.New("exactly one Windows client target is required")
		}
		if p.WindowsClient.Architecture != "x64" {
			return errors.New("the initial Windows client lifecycle supports only x64")
		}
	default:
		return errors.New("the deployment target is unsupported")
	}
	return nil
}

func safeHTTPSURL(value string) bool {
	u, err := url.Parse(value)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil
}

func composeHTTPSURL(value string) bool {
	u, err := url.Parse(value)
	return err == nil && safeHTTPSURL(value) && net.ParseIP(u.Hostname()) == nil
}

func validSha256(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func loopbackHTTPURL(value string) bool {
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "http" || u.User != nil {
		return false
	}
	host, _, _ := net.SplitHostPort(u.Host)
	return net.ParseIP(host).IsLoopback()
}

func redact(value string, secrets map[string]string) string {
	result := value
	for _, secret := range secrets {
		if secret != "" {
			result = strings.ReplaceAll(result, secret, "[REDACTED]")
		}
	}
	return result
}
