package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeVersion(t *testing.T) {
	for _, raw := range []string{"0.2.0-alpha.1", "v1.2.3"} {
		if _, err := normalizeVersion(raw); err != nil {
			t.Fatalf("normalizeVersion(%q): %v", raw, err)
		}
	}
	for _, raw := range []string{"", "v1", "01.2.3", "latest"} {
		if _, err := normalizeVersion(raw); err == nil {
			t.Fatalf("normalizeVersion(%q) succeeded", raw)
		}
	}
}

func TestReleaseWorkflowMatchesPrereleaseTags(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(raw)
	for _, required := range []string{
		`- "v*.*.*"`,
		"id-token: write",
		"environment: npm-release",
		"package-manager-cache: false",
	} {
		if !strings.Contains(workflow, required) {
			t.Fatalf("release workflow is missing %q", required)
		}
	}
	if strings.Contains(workflow, `v[0-9]+.[0-9]+.[0-9]+*`) {
		t.Fatal("release workflow uses a regular expression as a GitHub glob")
	}
}

func TestCheckSourceTreeIsGitIndependentAndBounded(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "docs", "guide.md")
	if err := os.WriteFile(path, []byte("safe source\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := checkSourceTree(root); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, []byte("trailing space \n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := checkSourceTree(root); err == nil || !strings.Contains(err.Error(), "trailing whitespace") {
		t.Fatalf("trailing whitespace error=%v", err)
	}

	if err := os.WriteFile(path, []byte("safe source\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "README.md")
	if err := os.Symlink(path, link); err != nil {
		t.Skipf("symbolic links unavailable: %v", err)
	}
	if err := checkSourceTree(root); err == nil || !strings.Contains(err.Error(), "symbolic link") {
		t.Fatalf("symbolic-link error=%v", err)
	}
}

func TestDeterministicArchives(t *testing.T) {
	files := []archiveFile{{Name: "nvault", Mode: 0o755, Data: []byte("binary")}, {Name: "README.md", Mode: 0o644, Data: []byte("readme")}}
	for _, format := range []string{"tar", "zip"} {
		first := filepath.Join(t.TempDir(), "first."+format)
		second := filepath.Join(t.TempDir(), "second."+format)
		var err error
		if format == "tar" {
			err = writeTarGzip(first, files)
			if err == nil {
				err = writeTarGzip(second, files)
			}
		} else {
			err = writeZip(first, files)
			if err == nil {
				err = writeZip(second, files)
			}
		}
		if err != nil {
			t.Fatal(err)
		}
		firstDigest, _ := fileSHA256(first)
		secondDigest, _ := fileSHA256(second)
		if firstDigest != secondDigest {
			t.Fatalf("%s archive is not deterministic", format)
		}
	}
}

func TestArchivesPreserveExecutableMode(t *testing.T) {
	files := []archiveFile{{Name: "nvault", Mode: 0o755, Data: []byte("binary")}}
	tarPath := filepath.Join(t.TempDir(), "nvault.tar.gz")
	if err := writeTarGzip(tarPath, files); err != nil {
		t.Fatal(err)
	}
	tarFile, _ := os.Open(tarPath)
	gzipReader, _ := gzip.NewReader(tarFile)
	header, _ := tar.NewReader(gzipReader).Next()
	if header.Mode != 0o755 {
		t.Fatalf("tar mode=%o", header.Mode)
	}
	zipPath := filepath.Join(t.TempDir(), "nvault.zip")
	if err := writeZip(zipPath, files); err != nil {
		t.Fatal(err)
	}
	zipReader, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := zipReader.Close(); err != nil {
			t.Errorf("close zip reader: %v", err)
		}
	}()
	if zipReader.File[0].Mode().Perm() != 0o755 {
		t.Fatalf("zip mode=%o", zipReader.File[0].Mode().Perm())
	}
}
