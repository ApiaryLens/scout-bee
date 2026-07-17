package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	sshAuthMethodSecret       = "sshAuthMethod"
	sshPrivateKeyPathSecret   = "sshPrivateKeyPath"
	sshPrivateKeyPhraseSecret = "sshPrivateKeyPassphrase"
	sshPasswordSecret         = "sshPassword"
	sshAskpassFileEnvironment = "APIARYLENS_SSH_ASKPASS_FILE"
)

type sshRuntimeAuth struct {
	options     []string
	environment map[string]string
	cleanup     func()
}

func prepareSSHRuntimeAuth(input request) (sshRuntimeAuth, error) {
	secrets := input.Secrets
	method := secrets[sshAuthMethodSecret]
	privateKeyPath := secrets[sshPrivateKeyPathSecret]
	privateKeyPassphrase := secrets[sshPrivateKeyPhraseSecret]
	password := secrets[sshPasswordSecret]
	if method == "" {
		method = "agent"
	}

	switch method {
	case "agent":
		if privateKeyPath != "" || privateKeyPassphrase != "" || password != "" {
			return sshRuntimeAuth{}, errors.New("SSH agent/default identity authentication cannot include a password, private-key path, or passphrase")
		}
		return sshRuntimeAuth{
			options:     []string{"-o", "BatchMode=yes", "-o", "IdentitiesOnly=no", "-o", "NumberOfPasswordPrompts=0"},
			environment: map[string]string{}, cleanup: func() {},
		}, nil
	case "private-key":
		if password != "" {
			return sshRuntimeAuth{}, errors.New("private-key SSH authentication cannot include a password")
		}
		if err := validatePrivateKeyPath(privateKeyPath); err != nil {
			return sshRuntimeAuth{}, err
		}
		options := []string{"-i", privateKeyPath, "-o", "IdentitiesOnly=yes"}
		if privateKeyPassphrase == "" {
			return sshRuntimeAuth{
				options:     append(options, "-o", "BatchMode=yes", "-o", "NumberOfPasswordPrompts=0"),
				environment: map[string]string{}, cleanup: func() {},
			}, nil
		}
		if err := validateAskpassSecret(privateKeyPassphrase); err != nil {
			return sshRuntimeAuth{}, fmt.Errorf("invalid SSH private-key passphrase: %w", err)
		}
		return prepareSSHAskpass(options, privateKeyPassphrase)
	case "password":
		if privateKeyPath != "" || privateKeyPassphrase != "" {
			return sshRuntimeAuth{}, errors.New("password SSH authentication cannot include a private-key path or passphrase")
		}
		if err := validateAskpassSecret(password); err != nil {
			return sshRuntimeAuth{}, fmt.Errorf("invalid SSH password: %w", err)
		}
		return prepareSSHAskpass([]string{
			"-o", "PreferredAuthentications=password,keyboard-interactive",
			"-o", "PubkeyAuthentication=no",
			"-o", "PasswordAuthentication=yes",
			"-o", "KbdInteractiveAuthentication=yes",
		}, password)
	default:
		return sshRuntimeAuth{}, errors.New("SSH authentication method must be agent, private-key, or password")
	}
}

func validatePrivateKeyPath(value string) error {
	if value == "" || !filepath.IsAbs(value) {
		return errors.New("private-key SSH authentication requires an absolute runtime-only key path")
	}
	info, err := os.Lstat(value)
	if err != nil {
		return errors.New("the selected SSH private key is not readable")
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("the selected SSH private key must be a regular file, not a link or directory")
	}
	return nil
}

func validateAskpassSecret(value string) error {
	if value == "" {
		return errors.New("a runtime-only value is required")
	}
	if len(value) > 16*1024 || strings.ContainsAny(value, "\x00\r\n") {
		return errors.New("the runtime-only value contains unsupported characters or is too large")
	}
	return nil
}

func prepareSSHAskpass(options []string, secret string) (sshRuntimeAuth, error) {
	if runtime.GOOS != "windows" {
		return sshRuntimeAuth{}, errors.New("password and passphrase SSH authentication currently require the packaged Windows Scout Bee; use an SSH agent or an unencrypted private key on this operating system")
	}
	executable, err := os.Executable()
	if err != nil || !filepath.IsAbs(executable) {
		return sshRuntimeAuth{}, errors.New("Scout could not locate its protected SSH credential helper")
	}
	directory, err := os.MkdirTemp("", "apiarylens-scout-askpass-")
	if err != nil {
		return sshRuntimeAuth{}, errors.New("Scout could not create protected temporary SSH credential storage")
	}
	cleanup := func() { _ = os.RemoveAll(directory) }
	if err = os.Chmod(directory, 0o700); err != nil {
		cleanup()
		return sshRuntimeAuth{}, errors.New("Scout could not protect temporary SSH credential storage")
	}
	secretPath := filepath.Join(directory, "credential")
	file, err := os.OpenFile(secretPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		cleanup()
		return sshRuntimeAuth{}, errors.New("Scout could not create its protected temporary SSH credential file")
	}
	_, writeErr := io.WriteString(file, secret)
	closeErr := file.Close()
	if writeErr != nil || closeErr != nil {
		cleanup()
		return sshRuntimeAuth{}, errors.New("Scout could not write its protected temporary SSH credential file")
	}
	return sshRuntimeAuth{
		options: append(options, "-o", "BatchMode=no", "-o", "NumberOfPasswordPrompts=1"),
		environment: map[string]string{
			"SSH_ASKPASS": executable, "SSH_ASKPASS_REQUIRE": "force", "DISPLAY": "ApiaryLens-Scout-Bee",
			sshAskpassFileEnvironment: secretPath,
		},
		cleanup: cleanup,
	}, nil
}

func runSSHAskpass(output io.Writer) (bool, int) {
	path := os.Getenv(sshAskpassFileEnvironment)
	if path == "" {
		return false, 0
	}
	temp, err := filepath.Abs(os.TempDir())
	if err != nil {
		return true, 1
	}
	absolute, err := filepath.Abs(path)
	if err != nil || filepath.Base(absolute) != "credential" || !strings.HasPrefix(filepath.Base(filepath.Dir(absolute)), "apiarylens-scout-askpass-") {
		return true, 1
	}
	relative, err := filepath.Rel(temp, absolute)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return true, 1
	}
	info, err := os.Lstat(absolute)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 16*1024 {
		return true, 1
	}
	raw, err := os.ReadFile(absolute)
	if err != nil || validateAskpassSecret(string(raw)) != nil {
		return true, 1
	}
	if _, err = fmt.Fprintln(output, string(raw)); err != nil {
		return true, 1
	}
	return true, 0
}
