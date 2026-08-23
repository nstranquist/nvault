package config

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestWriteLoadAndResolve(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "config.json")
	value := File{
		Format:         FormatV1,
		IdentityFile:   "identity.json",
		StoreDir:       "store",
		PassphraseFile: "passphrase.txt",
		DefaultScope:   "project:dev",
	}
	if err := WriteExclusive(path, value); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.IdentityFile != filepath.Join(root, "identity.json") ||
		loaded.StoreDir != filepath.Join(root, "store") ||
		loaded.PassphraseFile != filepath.Join(root, "passphrase.txt") ||
		loaded.DefaultScope != "project:dev" {
		t.Fatalf("loaded=%+v", loaded)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%#o", info.Mode().Perm())
	}
	if err := WriteExclusive(path, value); err == nil || !errors.Is(err, os.ErrExist) {
		t.Fatalf("second write err=%v", err)
	}
}

func TestLoadRejectsUnknownTrailingAndOversizedData(t *testing.T) {
	tests := map[string]string{
		"unknown":   `{"format":"nvault.config.v1","passphrase":"secret"}`,
		"duplicate": `{"format":"nvault.config.v1","format":"nvault.config.v1"}`,
		"trailing":  `{"format":"nvault.config.v1"} {}`,
		"format":    `{"format":"nvault.config.v2"}`,
		"oversize":  `{"format":"nvault.config.v1","default_scope":"` + strings.Repeat("x", MaximumFileSize) + `"}`,
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.json")
			if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatal("invalid config loaded")
			}
		})
	}
}

func TestLoadRejectsUnsafeFileTypesAndModes(t *testing.T) {
	root := t.TempDir()
	valid := []byte(`{"format":"nvault.config.v1"}`)
	if runtime.GOOS != "windows" {
		path := filepath.Join(root, "group-readable.json")
		if err := os.WriteFile(path, valid, 0o640); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "permissions") {
			t.Fatalf("mode err=%v", err)
		}
	}
	target := filepath.Join(root, "target.json")
	if err := os.WriteFile(target, valid, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.json")
	if err := os.Symlink(target, link); err == nil {
		if _, err := Load(link); err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("symlink err=%v", err)
		}
	}
}

func TestWriteExclusiveDoesNotChangeExistingParentPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not report POSIX permission bits")
	}
	parent := filepath.Join(t.TempDir(), "shared-config-parent")
	if err := os.Mkdir(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(parent, "nvault.json")
	if err := WriteExclusive(path, File{Format: FormatV1}); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("parent mode=%#o want 0755", info.Mode().Perm())
	}
}

func TestWriteExclusiveRejectsSymlinkParent(t *testing.T) {
	target := filepath.Join(t.TempDir(), "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := WriteExclusive(filepath.Join(link, "config.json"), File{Format: FormatV1}); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("symlink parent err=%v", err)
	}
}
