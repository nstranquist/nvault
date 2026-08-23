// Command nvault-release builds deterministic cross-platform CLI archives and
// a SHA-256 checksum file from one reviewed source tree.
package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	versionpkg "github.com/nstranquist/nvault/version"
)

type target struct {
	GOOS   string
	GOARCH string
}

var targets = []target{
	{GOOS: "darwin", GOARCH: "amd64"},
	{GOOS: "darwin", GOARCH: "arm64"},
	{GOOS: "linux", GOARCH: "amd64"},
	{GOOS: "linux", GOARCH: "arm64"},
	{GOOS: "windows", GOARCH: "amd64"},
	{GOOS: "windows", GOARCH: "arm64"},
}

var semver = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)

const (
	maxSourceFiles = 10_000
	maxSourceBytes = 2 << 20
)

func main() {
	flags := flag.NewFlagSet("nvault-release", flag.ExitOnError)
	requested := flags.String("version", "", "release version, with optional v prefix")
	output := flags.String("output", "dist", "new or empty artifact directory")
	checkSource := flags.String("check-source", "", "check a source tree without requiring Git metadata")
	if err := flags.Parse(os.Args[1:]); err != nil {
		fatal(err)
	}
	if flags.NArg() != 0 {
		fatal(errors.New("unexpected positional arguments"))
	}
	if *checkSource != "" {
		if *requested != "" {
			fatal(errors.New("--check-source cannot be combined with --version"))
		}
		if err := checkSourceTree(*checkSource); err != nil {
			fatal(err)
		}
		return
	}
	version, err := normalizeVersion(*requested)
	if err != nil {
		fatal(err)
	}
	if err := verifyVersions(version); err != nil {
		fatal(err)
	}
	if err := buildRelease(version, *output); err != nil {
		fatal(err)
	}
}

func checkSourceTree(root string) error {
	root = filepath.Clean(root)
	info, err := os.Stat(root)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("source root is not a directory")
	}
	files := 0
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if relative == "." {
			return nil
		}
		if entry.IsDir() && ignoredSourceDirectory(relative) {
			return fs.SkipDir
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("source path %s is a symbolic link", relative)
		}
		if entry.IsDir() || !releaseTextPath(relative) {
			return nil
		}
		files++
		if files > maxSourceFiles {
			return fmt.Errorf("source tree exceeds %d checked files", maxSourceFiles)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("source path %s is not a regular file", relative)
		}
		if info.Size() > maxSourceBytes {
			return fmt.Errorf("source path %s exceeds %d bytes", relative, maxSourceBytes)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.IndexByte(raw, 0) >= 0 {
			return fmt.Errorf("source path %s contains a NUL byte", relative)
		}
		if bytes.IndexByte(raw, '\r') >= 0 {
			return fmt.Errorf("source path %s contains a carriage return", relative)
		}
		if len(raw) > 0 && raw[len(raw)-1] != '\n' {
			return fmt.Errorf("source path %s has no final newline", relative)
		}
		for index, line := range bytes.Split(raw, []byte{'\n'}) {
			if len(line) > 0 && (line[len(line)-1] == ' ' || line[len(line)-1] == '\t') {
				return fmt.Errorf("source path %s has trailing whitespace on line %d", relative, index+1)
			}
		}
		return nil
	})
}

func ignoredSourceDirectory(path string) bool {
	switch path {
	case ".git", ".wip", "client/node_modules", "client/dist", "dist":
		return true
	default:
		return false
	}
}

func releaseTextPath(path string) bool {
	base := filepath.Base(path)
	if base == "Makefile" || base == "LICENSE" || base == ".gitignore" {
		return true
	}
	switch strings.ToLower(filepath.Ext(base)) {
	case ".go", ".json", ".md", ".mjs", ".ts", ".yaml", ".yml":
		return true
	default:
		return false
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "nvault-release:", err)
	os.Exit(1)
}

func normalizeVersion(raw string) (string, error) {
	value := strings.TrimPrefix(strings.TrimSpace(raw), "v")
	if !semver.MatchString(value) {
		return "", fmt.Errorf("version %q is not Semantic Versioning", raw)
	}
	return value, nil
}

func verifyVersions(requested string) error {
	if requested != versionpkg.Current {
		return fmt.Errorf("tag version %s does not match Go version %s", requested, versionpkg.Current)
	}
	raw, err := os.ReadFile(filepath.Join("client", "package.json"))
	if err != nil {
		return err
	}
	var manifest struct {
		Version string `json:"version"`
	}
	// package.json has many fields, so decode into a map first and validate the
	// one release field without accepting a non-string value.
	var document map[string]json.RawMessage
	if err := json.Unmarshal(raw, &document); err != nil {
		return err
	}
	if err := json.Unmarshal(document["version"], &manifest.Version); err != nil {
		return errors.New("client package version is missing or invalid")
	}
	if manifest.Version != requested {
		return fmt.Errorf("tag version %s does not match client version %s", requested, manifest.Version)
	}
	return nil
}

func buildRelease(version, output string) (returnErr error) {
	if err := ensureEmptyDirectory(output); err != nil {
		return err
	}
	temporary, err := os.MkdirTemp("", "nvault-release-")
	if err != nil {
		return err
	}
	defer func() {
		if err := os.RemoveAll(temporary); err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("remove temporary release directory: %w", err))
		}
	}()

	readme, err := os.ReadFile("README.md")
	if err != nil {
		return err
	}
	license, err := os.ReadFile("LICENSE")
	if err != nil {
		return err
	}
	checksums := map[string]string{}
	for _, current := range targets {
		name := fmt.Sprintf("nvault_%s_%s_%s", version, current.GOOS, current.GOARCH)
		binaryName := "nvault"
		if current.GOOS == "windows" {
			binaryName += ".exe"
		}
		binaryPath := filepath.Join(temporary, binaryName)
		command := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-ldflags", "-s -w -X main.version="+version, "-o", binaryPath, "./cmd/nvault")
		command.Env = append(os.Environ(), "CGO_ENABLED=0", "GOOS="+current.GOOS, "GOARCH="+current.GOARCH)
		command.Stdout = os.Stdout
		command.Stderr = os.Stderr
		if err := command.Run(); err != nil {
			return fmt.Errorf("build %s/%s: %w", current.GOOS, current.GOARCH, err)
		}
		binary, err := os.ReadFile(binaryPath)
		if err != nil {
			return err
		}
		files := []archiveFile{{Name: binaryName, Mode: 0o755, Data: binary}, {Name: "LICENSE", Mode: 0o644, Data: license}, {Name: "README.md", Mode: 0o644, Data: readme}}
		archiveName := name + ".tar.gz"
		if current.GOOS == "windows" {
			archiveName = name + ".zip"
		}
		archivePath := filepath.Join(output, archiveName)
		if current.GOOS == "windows" {
			err = writeZip(archivePath, files)
		} else {
			err = writeTarGzip(archivePath, files)
		}
		if err != nil {
			return err
		}
		digest, err := fileSHA256(archivePath)
		if err != nil {
			return err
		}
		checksums[archiveName] = digest
	}
	return writeChecksums(filepath.Join(output, "checksums.txt"), checksums)
}

func ensureEmptyDirectory(path string) error {
	if path == "" || filepath.Clean(path) == "." || filepath.IsAbs(path) && filepath.Clean(path) == string(filepath.Separator) {
		return errors.New("output must be a narrow artifact directory")
	}
	entries, err := os.ReadDir(path)
	if errors.Is(err, os.ErrNotExist) {
		return os.MkdirAll(path, 0o755)
	}
	if err != nil {
		return err
	}
	if len(entries) != 0 {
		return fmt.Errorf("output directory %s is not empty", path)
	}
	return nil
}

type archiveFile struct {
	Name string
	Mode int64
	Data []byte
}

var archiveTime = time.Date(1980, time.January, 1, 0, 0, 0, 0, time.UTC)

func writeTarGzip(path string, files []archiveFile) (returnErr error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	defer func() {
		if err := file.Close(); returnErr == nil {
			returnErr = err
		}
	}()
	gzipWriter, err := gzip.NewWriterLevel(file, gzip.BestCompression)
	if err != nil {
		return err
	}
	gzipWriter.Name = ""
	gzipWriter.Comment = ""
	gzipWriter.ModTime = archiveTime
	tarWriter := tar.NewWriter(gzipWriter)
	for _, item := range files {
		header := &tar.Header{Name: item.Name, Mode: item.Mode, Size: int64(len(item.Data)), ModTime: archiveTime, Typeflag: tar.TypeReg, Format: tar.FormatPAX}
		if err := tarWriter.WriteHeader(header); err != nil {
			return err
		}
		if _, err := tarWriter.Write(item.Data); err != nil {
			return err
		}
	}
	if err := tarWriter.Close(); err != nil {
		return err
	}
	return gzipWriter.Close()
}

func writeZip(path string, files []archiveFile) (returnErr error) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	defer func() {
		if err := file.Close(); returnErr == nil {
			returnErr = err
		}
	}()
	writer := zip.NewWriter(file)
	for _, item := range files {
		header := &zip.FileHeader{Name: item.Name, Method: zip.Deflate, Modified: archiveTime}
		header.SetMode(os.FileMode(item.Mode))
		entry, err := writer.CreateHeader(header)
		if err != nil {
			return err
		}
		if _, err := entry.Write(item.Data); err != nil {
			return err
		}
	}
	return writer.Close()
}

func fileSHA256(path string) (digest string, returnErr error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := file.Close(); err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("close %s: %w", path, err))
		}
	}()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func writeChecksums(path string, checksums map[string]string) error {
	names := make([]string, 0, len(checksums))
	for name := range checksums {
		names = append(names, name)
	}
	sort.Strings(names)
	var output strings.Builder
	for _, name := range names {
		fmt.Fprintf(&output, "%s  %s\n", checksums[name], name)
	}
	return os.WriteFile(path, []byte(output.String()), 0o644)
}
