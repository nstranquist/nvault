// Package config loads the non-secret settings used by the nvault CLI.
//
// Configuration files contain paths and a default scope. They never contain a
// passphrase or private key. Relative paths are resolved from the directory
// that contains the configuration file.
package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/nstranquist/nvault/internal/strictjson"
)

var scopePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,119}$`)

const (
	FormatV1        = "nvault.config.v1"
	MaximumFileSize = 64 << 10
)

// File is the nvault.config.v1 file format. An empty field uses the CLI
// default. PassphraseFile names a file; it never contains the passphrase.
type File struct {
	Format         string `json:"format"`
	IdentityFile   string `json:"identity_file,omitempty"`
	StoreDir       string `json:"store_dir,omitempty"`
	PassphraseFile string `json:"passphrase_file,omitempty"`
	DefaultScope   string `json:"default_scope,omitempty"`
}

// DefaultPath returns the user-level nvault configuration path.
func DefaultPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("config: find user configuration directory: %w", err)
	}
	return filepath.Join(dir, "nvault", "config.json"), nil
}

// Load reads and strictly validates one configuration file.
func Load(path string) (result File, returnErr error) {
	if strings.TrimSpace(path) == "" {
		return File{}, errors.New("config: file path is required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return File{}, fmt.Errorf("config: inspect %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return File{}, fmt.Errorf("config: %s is not a regular file", path)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return File{}, fmt.Errorf("config: %s permissions are %#o; remove group and other access", path, info.Mode().Perm())
	}
	if info.Size() > MaximumFileSize {
		return File{}, fmt.Errorf("config: %s exceeds %d bytes", path, MaximumFileSize)
	}
	file, err := os.Open(path)
	if err != nil {
		return File{}, fmt.Errorf("config: open %s: %w", path, err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("config: close %s: %w", path, err))
		}
	}()
	openedInfo, err := file.Stat()
	if err != nil {
		return File{}, fmt.Errorf("config: inspect opened %s: %w", path, err)
	}
	if !os.SameFile(info, openedInfo) {
		return File{}, fmt.Errorf("config: %s changed while it was opened", path)
	}
	raw, err := io.ReadAll(io.LimitReader(file, MaximumFileSize+1))
	if err != nil {
		return File{}, fmt.Errorf("config: read %s: %w", path, err)
	}
	if len(raw) > MaximumFileSize {
		return File{}, fmt.Errorf("config: %s exceeds %d bytes", path, MaximumFileSize)
	}
	if err := strictjson.Check(raw, 16); err != nil {
		return File{}, fmt.Errorf("config: %s contains invalid JSON: %w", path, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value File
	if err := decoder.Decode(&value); err != nil {
		return File{}, fmt.Errorf("config: decode %s: %w", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return File{}, fmt.Errorf("config: %s contains trailing JSON data", path)
	}
	if err := value.Validate(); err != nil {
		return File{}, fmt.Errorf("config: %s: %w", path, err)
	}
	return value.Resolve(filepath.Dir(path)), nil
}

// Validate rejects unsupported formats and ambiguous path values.
func (f File) Validate() error {
	if f.Format != FormatV1 {
		return fmt.Errorf("unsupported format %q", f.Format)
	}
	for name, value := range map[string]string{
		"identity_file":   f.IdentityFile,
		"store_dir":       f.StoreDir,
		"passphrase_file": f.PassphraseFile,
	} {
		if strings.IndexByte(value, 0) >= 0 {
			return fmt.Errorf("%s contains a NUL byte", name)
		}
	}
	if strings.IndexByte(f.DefaultScope, 0) >= 0 {
		return errors.New("default_scope contains a NUL byte")
	}
	if f.DefaultScope != "" && !scopePattern.MatchString(f.DefaultScope) {
		return errors.New("default_scope must match [A-Za-z0-9][A-Za-z0-9._:-]* and contain at most 120 characters")
	}
	return nil
}

// Resolve makes relative paths absolute against baseDir.
func (f File) Resolve(baseDir string) File {
	resolve := func(value string) string {
		if value == "" || filepath.IsAbs(value) {
			return value
		}
		return filepath.Clean(filepath.Join(baseDir, value))
	}
	f.IdentityFile = resolve(f.IdentityFile)
	f.StoreDir = resolve(f.StoreDir)
	f.PassphraseFile = resolve(f.PassphraseFile)
	return f
}

// WriteExclusive creates an owner-only configuration file. It never replaces
// an existing file.
func WriteExclusive(path string, value File) (returnErr error) {
	if strings.TrimSpace(path) == "" {
		return errors.New("config: file path is required")
	}
	if err := value.Validate(); err != nil {
		return fmt.Errorf("config: write: %w", err)
	}
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("config: encode: %w", err)
	}
	raw = append(raw, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("config: create directory: %w", err)
	}
	dirInfo, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("config: inspect directory: %w", err)
	}
	if !dirInfo.IsDir() {
		return fmt.Errorf("config: parent %s is not a directory", dir)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("config: open directory: %w", err)
	}
	defer func() {
		if err := root.Close(); err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("config: close directory: %w", err))
		}
	}()
	openedDirInfo, err := root.Stat(".")
	if err != nil {
		return fmt.Errorf("config: inspect opened directory: %w", err)
	}
	if !os.SameFile(dirInfo, openedDirInfo) {
		return errors.New("config: parent directory changed while it was opened")
	}
	name := filepath.Base(filepath.Clean(path))
	file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("config: create %s: %w", path, err)
	}
	keepFile := false
	fileClosed := false
	defer func() {
		if !fileClosed {
			if err := file.Close(); err != nil {
				returnErr = errors.Join(returnErr, fmt.Errorf("config: close %s: %w", path, err))
			}
		}
		if !keepFile {
			if err := root.Remove(name); err != nil && !errors.Is(err, os.ErrNotExist) {
				returnErr = errors.Join(returnErr, fmt.Errorf("config: remove incomplete %s: %w", path, err))
			}
		}
	}()
	if _, err := file.Write(raw); err != nil {
		return fmt.Errorf("config: write %s: %w", path, err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("config: sync %s: %w", path, err)
	}
	closeErr := file.Close()
	fileClosed = true
	if closeErr != nil {
		return fmt.Errorf("config: close %s: %w", path, closeErr)
	}
	if runtime.GOOS != "windows" {
		directory, err := root.Open(".")
		if err != nil {
			return fmt.Errorf("config: open directory: %w", err)
		}
		syncErr := directory.Sync()
		closeErr := directory.Close()
		if syncErr != nil || closeErr != nil {
			return errors.Join(
				wrapError("config: sync directory", syncErr),
				wrapError("config: close directory", closeErr),
			)
		}
	}
	keepFile = true
	return nil
}

func wrapError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}
