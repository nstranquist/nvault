package store

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/nstranquist/nvault/crypto"
)

func testVault(t *testing.T) (*Vault, crypto.Identity) {
	t.Helper()
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	vault, err := Open(dir, id)
	if err != nil {
		t.Fatal(err)
	}
	return vault, id
}

func TestSetGetListDelete(t *testing.T) {
	vault, _ := testVault(t)
	if err := vault.Set("global", "DB_URL", "secret", []byte("postgres://private")); err != nil {
		t.Fatal(err)
	}
	plaintext, metadata, err := vault.Get("global", "DB_URL")
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != "postgres://private" || metadata.Key != "DB_URL" {
		t.Fatalf("plaintext=%q metadata=%+v", plaintext, metadata)
	}
	items, err := vault.List("global")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Key != "DB_URL" {
		t.Fatalf("items=%+v", items)
	}
	if err := vault.Delete("global", "DB_URL"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := vault.Get("global", "DB_URL"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get after delete: %v", err)
	}
}

func TestSlotRelocationAndWrongIdentityFail(t *testing.T) {
	vault, _ := testVault(t)
	if err := vault.Set("dev", "TOKEN", "secret", []byte("value")); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(vault.itemPath("dev", "TOKEN"))
	if err != nil {
		t.Fatal(err)
	}
	var record Item
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	record.Scope = "prod"
	relocated, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	itemsDir := filepath.Join(vault.dir, "items")
	if err := os.WriteFile(filepath.Join(itemsDir, slotName("prod", "TOKEN")), relocated, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := vault.Get("prod", "TOKEN"); !errors.Is(err, crypto.ErrAADMismatch) {
		t.Fatalf("relocated get: %v", err)
	}

	other, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	wrongVault, err := Open(vault.dir, other)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := wrongVault.Get("dev", "TOKEN"); !errors.Is(err, crypto.ErrNoMatchingRecipient) {
		t.Fatalf("wrong identity: %v", err)
	}
}

func TestFilesAreOwnerOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not report POSIX permission bits")
	}
	vault, _ := testVault(t)
	if err := vault.Set("global", "TOKEN", "secret", []byte("value")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(vault.itemPath("global", "TOKEN"))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("item mode=%#o", got)
	}
}

func TestValidateSlot(t *testing.T) {
	for _, test := range []struct {
		scope string
		key   string
	}{
		{"../prod", "TOKEN"},
		{"global", "../TOKEN"},
		{"global", "NOT VALID"},
	} {
		if err := ValidateSlot(test.scope, test.key); err == nil {
			t.Fatalf("ValidateSlot(%q,%q) succeeded", test.scope, test.key)
		}
	}
}

func TestListRejectsUnboundedUnknownAndTrailingRecords(t *testing.T) {
	for name, mutate := range map[string]func([]byte) []byte{
		"oversized": func(raw []byte) []byte {
			return append(raw, []byte(strings.Repeat(" ", crypto.MaxEnvelopeJSONSize+4096))...)
		},
		"unknown": func(raw []byte) []byte {
			return []byte(strings.Replace(string(raw), `"format":`, `"unknown":true,"format":`, 1))
		},
		"duplicate": func(raw []byte) []byte {
			return []byte(strings.Replace(string(raw), `"format":`, `"format":"nvault.store.v1","format":`, 1))
		},
		"trailing": func(raw []byte) []byte {
			return append(raw, []byte("{}")...)
		},
	} {
		t.Run(name, func(t *testing.T) {
			vault, _ := testVault(t)
			if err := vault.Set("global", "TOKEN", "secret", []byte("value")); err != nil {
				t.Fatal(err)
			}
			path := vault.itemPath("global", "TOKEN")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, mutate(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := vault.List("global"); err == nil {
				t.Fatal("invalid record was listed")
			}
		})
	}
}

func TestGetRejectsTrailingRecordData(t *testing.T) {
	vault, _ := testVault(t)
	if err := vault.Set("global", "TOKEN", "secret", []byte("value")); err != nil {
		t.Fatal(err)
	}
	path := vault.itemPath("global", "TOKEN")
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("{}\n"); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := vault.Get("global", "TOKEN"); err == nil || !strings.Contains(err.Error(), "trailing") {
		t.Fatalf("get err=%v", err)
	}
}

func TestOpenAndReadsRejectUnsafeModesAndSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not report POSIX permission bits")
	}
	id, err := crypto.GenerateIdentity()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err := os.Chmod(root, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(root, id); err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("open err=%v", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "store-link")
	if err := os.Symlink(root, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link, id); err == nil || !strings.Contains(err.Error(), "not a directory") {
		t.Fatalf("symlink open err=%v", err)
	}

	vault, err := Open(root, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := vault.Set("global", "TOKEN", "secret", []byte("value")); err != nil {
		t.Fatal(err)
	}
	itemPath := vault.itemPath("global", "TOKEN")
	if err := os.Chmod(itemPath, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, _, err := vault.Get("global", "TOKEN"); err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("get mode err=%v", err)
	}
	if err := os.Chmod(itemPath, 0o600); err != nil {
		t.Fatal(err)
	}
	itemsDir := filepath.Join(root, "items")
	if err := os.Chmod(itemsDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := vault.List("global"); err == nil || !strings.Contains(err.Error(), "permissions") {
		t.Fatalf("list mode err=%v", err)
	}
}

func TestOperationsRejectSymlinkedItemsDirectory(t *testing.T) {
	vault, _ := testVault(t)
	target := t.TempDir()
	itemsDir := filepath.Join(vault.dir, "items")
	if err := os.Symlink(target, itemsDir); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := vault.Set("global", "TOKEN", "secret", []byte("value")); err == nil || !strings.Contains(err.Error(), "items path is not a directory") {
		t.Fatalf("set through items symlink err=%v", err)
	}
	if _, err := vault.List("global"); err == nil || !strings.Contains(err.Error(), "items path is not a directory") {
		t.Fatalf("list through items symlink err=%v", err)
	}
	if err := vault.Delete("global", "TOKEN"); err == nil || !strings.Contains(err.Error(), "items path is not a directory") {
		t.Fatalf("delete through items symlink err=%v", err)
	}
	entries, err := os.ReadDir(target)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("operation escaped into symlink target: %v", entries)
	}
}

func TestOperationsRejectSymlinkedItemFile(t *testing.T) {
	vault, _ := testVault(t)
	if err := vault.Set("global", "TOKEN", "secret", []byte("value")); err != nil {
		t.Fatal(err)
	}
	itemPath := vault.itemPath("global", "TOKEN")
	if err := os.Remove(itemPath); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "external.json")
	if err := os.WriteFile(target, []byte("external"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, itemPath); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if _, _, err := vault.Get("global", "TOKEN"); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("get through item symlink err=%v", err)
	}
	if _, err := vault.List("global"); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("list through item symlink err=%v", err)
	}
	if err := vault.Delete("global", "TOKEN"); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("delete through item symlink err=%v", err)
	}
	if raw, err := os.ReadFile(target); err != nil || string(raw) != "external" {
		t.Fatalf("external target changed: raw=%q err=%v", raw, err)
	}
}
