package main

import (
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const diagnosticsSchemaVersion = 1

var (
	diagnosticVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-(?:preview|rc)\.[0-9]+)?$`)
	sourceCommit      = regexp.MustCompile(`^[0-9a-fA-F]{40,64}$`)
	apiContract       = regexp.MustCompile(`^[0-9]+\.[0-9]+(?:\.[0-9]+)?$`)
	migrationHead     = regexp.MustCompile(`^[0-9]{4,8}$`)
)

// releaseVerificationMetadata is deliberately smaller than releaseManifest. It
// records only immutable verification evidence; artifact names and URLs are never
// persisted because they can contain paths, query values, or operator identifiers.
type releaseVerificationMetadata struct {
	ProductVersion   string                           `json:"productVersion"`
	Channel          string                           `json:"channel"`
	ManifestSha256   string                           `json:"manifestSha256"`
	SourceCommit     string                           `json:"sourceCommit,omitempty"`
	BuildTime        string                           `json:"buildTime,omitempty"`
	Contracts        diagnosticContracts              `json:"contracts"`
	Artifacts        []diagnosticArtifactVerification `json:"artifacts,omitempty"`
	ManifestVerified bool                             `json:"manifestVerified"`
}

type diagnosticContracts struct {
	API               string `json:"api,omitempty"`
	Sync              int    `json:"sync,omitempty"`
	DatabaseMigration string `json:"databaseMigration,omitempty"`
	DeploymentPlan    int    `json:"deploymentPlan,omitempty"`
}

type diagnosticArtifactVerification struct {
	Kind   string `json:"kind"`
	Target string `json:"target"`
	Sha256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
}

type diagnosticsBundle struct {
	SchemaVersion       int                         `json:"schemaVersion"`
	Product             string                      `json:"product"`
	ScoutVersion        string                      `json:"scoutVersion"`
	GeneratedAt         time.Time                   `json:"generatedAt"`
	Operation           diagnosticWindowsOperation  `json:"operation"`
	ReleaseVerification releaseVerificationMetadata `json:"releaseVerification"`
	Privacy             diagnosticPrivacy           `json:"privacy"`
}

type diagnosticWindowsOperation struct {
	OperationID string            `json:"operationId"`
	Target      string            `json:"target"`
	Action      string            `json:"action"`
	Mode        string            `json:"mode"`
	Status      string            `json:"status"`
	StartedAt   time.Time         `json:"startedAt"`
	FinishedAt  *time.Time        `json:"finishedAt,omitempty"`
	Checks      []diagnosticCheck `json:"checks,omitempty"`
}

type diagnosticCheck struct {
	Code  string `json:"code"`
	State string `json:"state"`
}

type diagnosticPrivacy struct {
	Sanitized bool     `json:"sanitized"`
	Excluded  []string `json:"excluded"`
}

var diagnosticPhaseCodes = map[string]string{
	"Validate deployment plan":                       "plan_validated",
	"Check release identity":                         "release_identity_verified",
	"Validate Windows client lifecycle plan":         "windows_plan_validated",
	"Verify Windows lifecycle operation":             "windows_operation_supported",
	"Verify Windows execution environment":           "windows_environment_verified",
	"Plan explicit permanent data removal":           "permanent_removal_planned",
	"Require permanent-delete confirmation":          "permanent_removal_confirmed",
	"Select Windows package manifest":                "package_manifest_selected",
	"Download and verify Windows package manifest":   "package_manifest_verified",
	"Verify Windows package identity":                "package_identity_verified",
	"Verify rollback availability":                   "rollback_available",
	"Download and verify Windows package":            "package_artifacts_verified",
	"Stage verified Windows package":                 "package_staged",
	"Verify Windows setup signature":                 "setup_authenticode_verified",
	"Apply Windows client install":                   "windows_install_applied",
	"Apply Windows client update":                    "windows_update_applied",
	"Apply Windows client repair":                    "windows_repair_applied",
	"Apply Windows client rollback":                  "windows_rollback_applied",
	"Locate installed Windows client":                "installed_client_located",
	"Verify installed Windows application signature": "installed_authenticode_verified",
	"Verify installed Windows client health":         "installed_health_verified",
	"Verify installed Windows client state":          "installed_state_verified",
	"Verify Windows lifecycle transition":            "lifecycle_transition_verified",
	"Protect Windows client data":                    "client_data_protected",
	"Record Windows lifecycle state":                 "lifecycle_state_recorded",
	"Locate Windows uninstaller":                     "uninstaller_located",
	"Verify Windows uninstaller signature":           "uninstaller_authenticode_verified",
	"Uninstall Windows application":                  "application_uninstalled",
	"Retain Windows client data":                     "client_data_retained",
	"Record keep-data uninstall":                     "keep_data_uninstall_recorded",
}

var diagnosticOperations = map[string]bool{
	"install": true, "update": true, "repair": true, "rollback": true,
	"backup": true, "restore": true, "export": true, "uninstall": true,
}

var diagnosticModes = map[string]bool{"dry-run": true, "apply": true, "resume": true}
var diagnosticStatuses = map[string]bool{"running": true, "passed": true, "failed": true, "canceled": true}
var diagnosticCheckStates = map[string]bool{"passed": true, "failed": true}

func buildReleaseVerification(expected release, manifest *releaseManifest) *releaseVerificationMetadata {
	if manifest == nil || manifest.Product != "ApiaryLens" || manifest.ProductVersion != expected.Version ||
		manifest.Channel != expected.Channel || !diagnosticVersion.MatchString(manifest.ProductVersion) ||
		!validDiagnosticChannel(manifest.Channel) || !validSha256(expected.ManifestSha256) {
		return nil
	}
	result := &releaseVerificationMetadata{
		ProductVersion:   manifest.ProductVersion,
		Channel:          manifest.Channel,
		ManifestSha256:   strings.ToLower(expected.ManifestSha256),
		ManifestVerified: true,
	}
	if sourceCommit.MatchString(manifest.SourceCommit) {
		result.SourceCommit = strings.ToLower(manifest.SourceCommit)
	}
	if parsed, err := time.Parse(time.RFC3339, manifest.BuildTime); err == nil {
		result.BuildTime = parsed.UTC().Format(time.RFC3339)
	}
	if apiContract.MatchString(manifest.Contracts.APIVersion) {
		result.Contracts.API = manifest.Contracts.APIVersion
	}
	if manifest.Contracts.Sync > 0 && manifest.Contracts.Sync < 1000 {
		result.Contracts.Sync = manifest.Contracts.Sync
	}
	if migrationHead.MatchString(manifest.Contracts.DatabaseMigration) {
		result.Contracts.DatabaseMigration = manifest.Contracts.DatabaseMigration
	}
	if manifest.Contracts.DeploymentPlan > 0 && manifest.Contracts.DeploymentPlan < 1000 {
		result.Contracts.DeploymentPlan = manifest.Contracts.DeploymentPlan
	}
	for _, artifact := range manifest.Artifacts {
		if artifact.Target != windowsTarget || !validSha256(artifact.Sha256) || artifact.Bytes <= 0 ||
			(artifact.Kind != "windows-package-manifest" && artifact.Kind != "windows-package-artifact") {
			continue
		}
		result.Artifacts = append(result.Artifacts, diagnosticArtifactVerification{
			Kind: artifact.Kind, Target: artifact.Target,
			Sha256: strings.ToLower(artifact.Sha256), Bytes: artifact.Bytes,
		})
	}
	return result
}

func buildDiagnosticsBundle(state operationState, generatedAt time.Time) (diagnosticsBundle, error) {
	if state.Plan.Target != "windows-client" || state.Plan.WindowsClient == nil {
		return diagnosticsBundle{}, errors.New("sanitized diagnostics are currently available only for Windows lifecycle operations")
	}
	if !planID.MatchString(state.Plan.PlanID) || !diagnosticOperations[state.Plan.Operation] ||
		!diagnosticModes[state.Mode] || !diagnosticStatuses[state.Status] || state.Verification == nil {
		return diagnosticsBundle{}, errors.New("the Windows lifecycle diagnostics state is incomplete")
	}
	verification := sanitizeReleaseVerification(*state.Verification)
	if !verification.ManifestVerified {
		return diagnosticsBundle{}, errors.New("verified release metadata is unavailable")
	}
	checks := make([]diagnosticCheck, 0, len(state.Phases))
	for _, item := range state.Phases {
		code, known := diagnosticPhaseCodes[item.Name]
		if !known || !diagnosticCheckStates[item.State] {
			continue
		}
		checks = append(checks, diagnosticCheck{Code: code, State: item.State})
	}
	version := "unknown"
	if diagnosticVersion.MatchString(scoutVersion) {
		version = scoutVersion
	}
	return diagnosticsBundle{
		SchemaVersion: diagnosticsSchemaVersion,
		Product:       "ApiaryLens Scout Bee", ScoutVersion: version, GeneratedAt: generatedAt.UTC(),
		Operation: diagnosticWindowsOperation{
			OperationID: state.Plan.PlanID, Target: "windows-client", Action: state.Plan.Operation,
			Mode: state.Mode, Status: state.Status, StartedAt: state.StartedAt.UTC(),
			FinishedAt: utcTimePointer(state.FinishedAt), Checks: checks,
		},
		ReleaseVerification: verification,
		Privacy: diagnosticPrivacy{
			Sanitized: true,
			Excluded:  []string{"credentials", "tokens", "user paths", "hive data", "media", "phase details", "artifact names", "artifact URLs"},
		},
	}, nil
}

func sanitizeReleaseVerification(value releaseVerificationMetadata) releaseVerificationMetadata {
	if !value.ManifestVerified || !diagnosticVersion.MatchString(value.ProductVersion) ||
		!validDiagnosticChannel(value.Channel) || !validSha256(value.ManifestSha256) {
		return releaseVerificationMetadata{}
	}
	result := releaseVerificationMetadata{
		ProductVersion: value.ProductVersion, Channel: value.Channel,
		ManifestSha256: strings.ToLower(value.ManifestSha256), ManifestVerified: true,
	}
	if sourceCommit.MatchString(value.SourceCommit) {
		result.SourceCommit = strings.ToLower(value.SourceCommit)
	}
	if parsed, err := time.Parse(time.RFC3339, value.BuildTime); err == nil {
		result.BuildTime = parsed.UTC().Format(time.RFC3339)
	}
	if apiContract.MatchString(value.Contracts.API) {
		result.Contracts.API = value.Contracts.API
	}
	if value.Contracts.Sync > 0 && value.Contracts.Sync < 1000 {
		result.Contracts.Sync = value.Contracts.Sync
	}
	if migrationHead.MatchString(value.Contracts.DatabaseMigration) {
		result.Contracts.DatabaseMigration = value.Contracts.DatabaseMigration
	}
	if value.Contracts.DeploymentPlan > 0 && value.Contracts.DeploymentPlan < 1000 {
		result.Contracts.DeploymentPlan = value.Contracts.DeploymentPlan
	}
	for _, artifact := range value.Artifacts {
		if artifact.Target == windowsTarget && validSha256(artifact.Sha256) && artifact.Bytes > 0 &&
			(artifact.Kind == "windows-package-manifest" || artifact.Kind == "windows-package-artifact") {
			result.Artifacts = append(result.Artifacts, diagnosticArtifactVerification{
				Kind: artifact.Kind, Target: artifact.Target,
				Sha256: strings.ToLower(artifact.Sha256), Bytes: artifact.Bytes,
			})
		}
	}
	return result
}

func validDiagnosticChannel(value string) bool {
	return value == "stable" || value == "preview" || value == "release-candidate"
}

func utcTimePointer(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	result := value.UTC()
	return &result
}

func (e *executor) diagnosticsHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResponse(w, http.StatusMethodNotAllowed, map[string]string{"message": "Method not allowed"})
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/diagnostics/")
	state, err := e.store.load(id)
	if err != nil {
		jsonResponse(w, http.StatusNotFound, map[string]string{"message": "Operation not found"})
		return
	}
	bundle, err := buildDiagnosticsBundle(state, time.Now())
	if err != nil {
		jsonResponse(w, http.StatusConflict, map[string]string{"message": err.Error()})
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="apiarylens-scout-diagnostics-`+id+`.json"`)
	jsonResponse(w, http.StatusOK, bundle)
}
