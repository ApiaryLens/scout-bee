package main

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func extractTarGz(path, destination string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	gz, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	root, err := filepath.Abs(destination)
	if err != nil {
		return err
	}
	for {
		header, nextErr := reader.Next()
		if errors.Is(nextErr, io.EOF) {
			return nil
		}
		if nextErr != nil {
			return nextErr
		}
		clean := filepath.Clean(header.Name)
		if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return errors.New("deployment bundle contains an unsafe path")
		}
		target := filepath.Join(root, clean)
		if target != root && !strings.HasPrefix(target, root+string(filepath.Separator)) {
			return errors.New("deployment bundle escapes its destination")
		}
		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
		case tar.TypeReg:
			if header.Size > 512<<20 {
				return errors.New("deployment bundle entry is too large")
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				return err
			}
			_, copyErr := io.CopyN(out, reader, header.Size)
			closeErr := out.Close()
			if copyErr != nil || closeErr != nil {
				return errors.Join(copyErr, closeErr)
			}
		default:
			return errors.New("deployment bundle contains an unsupported link or device")
		}
	}
}
