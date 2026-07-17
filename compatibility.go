package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
)

type scoutCompatibility struct {
	SchemaVersion            int      `json:"schemaVersion"`
	ScoutVersion             string   `json:"scoutVersion"`
	SupportedProductVersions []string `json:"supportedProductVersions"`
	TestedProductVersions    []string `json:"testedProductVersions"`
}

//go:embed compatibility.json
var embeddedCompatibility []byte

var (
	compatibilityOnce sync.Once
	compatibilityData scoutCompatibility
	compatibilityErr  error
)

func loadCompatibility() (scoutCompatibility, error) {
	compatibilityOnce.Do(func() {
		if err := json.Unmarshal(embeddedCompatibility, &compatibilityData); err != nil {
			compatibilityErr = errors.New("embedded Scout compatibility metadata is invalid")
			return
		}
		if compatibilityData.SchemaVersion != 1 || compatibilityData.ScoutVersion != scoutVersion {
			compatibilityErr = errors.New("embedded Scout compatibility identity does not match this executable")
			return
		}
		if len(compatibilityData.SupportedProductVersions) == 0 || len(compatibilityData.TestedProductVersions) == 0 {
			compatibilityErr = errors.New("embedded Scout compatibility metadata has no supported and tested product versions")
			return
		}
		tested := make(map[string]bool, len(compatibilityData.TestedProductVersions))
		for _, version := range compatibilityData.TestedProductVersions {
			if version == "" || tested[version] {
				compatibilityErr = errors.New("embedded Scout compatibility metadata contains an empty or duplicate tested product version")
				return
			}
			tested[version] = true
		}
		supported := make(map[string]bool, len(compatibilityData.SupportedProductVersions))
		for _, version := range compatibilityData.SupportedProductVersions {
			if version == "" || supported[version] {
				compatibilityErr = errors.New("embedded Scout compatibility metadata contains an empty or duplicate supported product version")
				return
			}
			if !tested[version] {
				compatibilityErr = fmt.Errorf("supported product version %s has no tested compatibility evidence", version)
				return
			}
			supported[version] = true
		}
	})
	return compatibilityData, compatibilityErr
}

func compatibleProductVersion(version string) bool {
	compatibility, err := loadCompatibility()
	if err != nil {
		return false
	}
	for _, supported := range compatibility.SupportedProductVersions {
		if version == supported {
			return true
		}
	}
	return false
}
