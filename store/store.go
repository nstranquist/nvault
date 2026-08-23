// Package store provides a small encrypted-at-rest local nvault store.
//
// Every value is an nvault.enc.v1 envelope. The logical scope and key are
// authenticated as associated data, so moving a file cannot change its slot.
package store

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/nstranquist/nvault/crypto"
	"github.com/nstranquist/nvault/internal/strictjson"
)

const (
	DefaultScope        = "global"
	formatV1            = "nvault.store.v1"
	maximumItemFileSize = int64(crypto.MaxEnvelopeJSONSize + 4096)
)

var (
	keyPattern   = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,255}$`)
	scopePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,119}$`)
	ErrNotFound  = errors.New("store: item not found")
)

// Item is the encrypted on-disk record. Plaintext never appears in this type.
type Item struct {
	Format    string          `json:"format"`
	Scope     string          `json:"scope"`
	Key       string          `json:"key"`
	Kind      string          `json:"kind"`
	Envelope  crypto.Envelope `json:"envelope"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// Metadata is safe to show in list output.
type Metadata struct {
	Scope     string    `json:"scope"`
	Key       string    `json:"key"`
	Kind      string    `json:"kind"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Vault binds a directory to the identity that opens its values.
type Vault struct {
	dir      string
	identity crypto.Identity
}

// Open validates the path and returns a local vault. The directory is created
// lazily on the first write.
func Open(dir string, identity crypto.Identity) (*Vault, error) {
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("store: directory is required")
	}
	if identity.Public == (crypto.PublicKey{}) {
		return nil, errors.New("store: identity is required")
	}
	if root, err := openPrivateDirectory(dir, "directory"); err == nil {
		if closeErr := root.Close(); closeErr != nil {
			return nil, fmt.Errorf("store: close directory: %w", closeErr)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return &Vault{dir: filepath.Clean(dir), identity: identity}, nil
}

// AAD returns the canonical authenticated slot for a local item.
func AAD(scope, key string) (string, error) {
	if err := ValidateSlot(scope, key); err != nil {
		return "", err
	}
	return "local/" + scope + "/" + key, nil
}

// ValidateSlot rejects ambiguous names and filesystem traversal characters.
func ValidateSlot(scope, key string) error {
	if !scopePattern.MatchString(scope) {
		return errors.New("store: scope must match [A-Za-z0-9][A-Za-z0-9._:-]* and contain at most 120 characters")
	}
	if !keyPattern.MatchString(key) {
		return errors.New("store: key must match [A-Za-z_][A-Za-z0-9_.-]* and contain at most 256 characters")
	}
	return nil
}

func validateKind(kind string) error {
	if kind != "secret" && kind != "param" {
		return errors.New("store: kind must be secret or param")
	}
	return nil
}

func slotName(scope, key string) string {
	sum := sha256.Sum256([]byte(scope + "\x00" + key))
	return hex.EncodeToString(sum[:]) + ".json"
}

func (v *Vault) itemPath(scope, key string) string {
	return filepath.Join(v.dir, "items", slotName(scope, key))
}

// Set encrypts and atomically writes one value.
func (v *Vault) Set(scope, key, kind string, plaintext []byte) (returnErr error) {
	aad, err := AAD(scope, key)
	if err != nil {
		return err
	}
	if err := validateKind(kind); err != nil {
		return err
	}
	envelope, err := crypto.Encrypt(plaintext, []crypto.Recipient{v.identity.Recipient("local")}, aad)
	if err != nil {
		return fmt.Errorf("store: encrypt: %w", err)
	}
	record := Item{
		Format:    formatV1,
		Scope:     scope,
		Key:       key,
		Kind:      kind,
		Envelope:  *envelope,
		UpdatedAt: time.Now().UTC(),
	}
	raw, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("store: encode item: %w", err)
	}
	raw = append(raw, '\n')
	itemsRoot, err := v.openItems(true)
	if err != nil {
		return err
	}
	defer func() {
		returnErr = errors.Join(returnErr, wrapStoreError("store: close items directory", itemsRoot.Close()))
	}()
	temporary, temporaryName, err := createTemporaryItem(itemsRoot)
	if err != nil {
		return fmt.Errorf("store: create temporary item: %w", err)
	}
	defer func() {
		if err := itemsRoot.Remove(temporaryName); err != nil && !errors.Is(err, os.ErrNotExist) {
			returnErr = errors.Join(returnErr, fmt.Errorf("store: remove temporary item: %w", err))
		}
	}()
	if _, err := temporary.Write(raw); err != nil {
		return errors.Join(
			fmt.Errorf("store: write temporary item: %w", err),
			wrapStoreError("store: close temporary item", temporary.Close()),
		)
	}
	if err := temporary.Sync(); err != nil {
		return errors.Join(
			fmt.Errorf("store: sync temporary item: %w", err),
			wrapStoreError("store: close temporary item", temporary.Close()),
		)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("store: close temporary item: %w", err)
	}
	if err := itemsRoot.Rename(temporaryName, slotName(scope, key)); err != nil {
		return fmt.Errorf("store: replace item: %w", err)
	}
	if err := syncRoot(itemsRoot); err != nil {
		return fmt.Errorf("store: sync items directory: %w", err)
	}
	return nil
}

func (v *Vault) read(scope, key string) (result *Item, returnErr error) {
	aad, err := AAD(scope, key)
	if err != nil {
		return nil, err
	}
	itemsRoot, err := v.openItems(false)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	defer func() {
		returnErr = errors.Join(returnErr, wrapStoreError("store: close items directory", itemsRoot.Close()))
	}()
	raw, err := readRegularFile(itemsRoot, slotName(scope, key))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: read item: %w", err)
	}
	if err := strictjson.Check(raw, 16); err != nil {
		return nil, fmt.Errorf("store: invalid item JSON: %w", err)
	}
	var record Item
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return nil, fmt.Errorf("store: decode item: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("store: item contains trailing JSON data")
	}
	if record.Format != formatV1 || record.Scope != scope || record.Key != key {
		return nil, errors.New("store: item metadata does not match its requested slot")
	}
	if err := validateKind(record.Kind); err != nil {
		return nil, err
	}
	if record.Envelope.AAD != aad {
		return nil, crypto.ErrAADMismatch
	}
	if err := crypto.ValidateEnvelope(&record.Envelope); err != nil {
		return nil, err
	}
	return &record, nil
}

// Get decrypts one value and verifies that it belongs to the requested slot.
func (v *Vault) Get(scope, key string) ([]byte, Metadata, error) {
	record, err := v.read(scope, key)
	if err != nil {
		return nil, Metadata{}, err
	}
	plaintext, err := crypto.Decrypt(&record.Envelope, v.identity, record.Envelope.AAD)
	if err != nil {
		return nil, Metadata{}, fmt.Errorf("store: decrypt: %w", err)
	}
	return plaintext, Metadata{Scope: record.Scope, Key: record.Key, Kind: record.Kind, UpdatedAt: record.UpdatedAt}, nil
}

// List returns metadata only. It validates every record and never decrypts or
// returns a value.
func (v *Vault) List(scope string) (result []Metadata, returnErr error) {
	if !scopePattern.MatchString(scope) {
		return nil, errors.New("store: invalid scope")
	}
	itemsRoot, err := v.openItems(false)
	if errors.Is(err, os.ErrNotExist) {
		return []Metadata{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer func() {
		returnErr = errors.Join(returnErr, wrapStoreError("store: close items directory", itemsRoot.Close()))
	}()
	directory, err := itemsRoot.Open(".")
	if err != nil {
		return nil, fmt.Errorf("store: open items directory: %w", err)
	}
	entries, err := directory.ReadDir(-1)
	closeErr := directory.Close()
	if err != nil {
		return nil, fmt.Errorf("store: list items: %w", err)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("store: close items directory: %w", closeErr)
	}
	items := make([]Metadata, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		raw, err := readRegularFile(itemsRoot, entry.Name())
		if err != nil {
			return nil, fmt.Errorf("store: read %s: %w", entry.Name(), err)
		}
		if err := strictjson.Check(raw, 16); err != nil {
			return nil, fmt.Errorf("store: invalid %s JSON: %w", entry.Name(), err)
		}
		var record Item
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&record); err != nil {
			return nil, fmt.Errorf("store: decode %s: %w", entry.Name(), err)
		}
		var trailing any
		if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("store: %s contains trailing JSON data", entry.Name())
		}
		if record.Format != formatV1 || record.Scope != scope {
			continue
		}
		if err := ValidateSlot(record.Scope, record.Key); err != nil {
			return nil, fmt.Errorf("store: invalid %s: %w", entry.Name(), err)
		}
		if slotName(record.Scope, record.Key) != entry.Name() {
			return nil, fmt.Errorf("store: %s does not match its slot metadata", entry.Name())
		}
		if err := validateKind(record.Kind); err != nil {
			return nil, fmt.Errorf("store: invalid %s: %w", entry.Name(), err)
		}
		expectedAAD, err := AAD(record.Scope, record.Key)
		if err != nil {
			return nil, fmt.Errorf("store: invalid %s: %w", entry.Name(), err)
		}
		if record.Envelope.AAD != expectedAAD {
			return nil, fmt.Errorf("store: invalid %s: %w", entry.Name(), crypto.ErrAADMismatch)
		}
		if err := crypto.ValidateEnvelope(&record.Envelope); err != nil {
			return nil, fmt.Errorf("store: invalid %s: %w", entry.Name(), err)
		}
		items = append(items, Metadata{Scope: record.Scope, Key: record.Key, Kind: record.Kind, UpdatedAt: record.UpdatedAt})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Key < items[j].Key })
	return items, nil
}

// Delete removes one encrypted item. It is idempotent.
func (v *Vault) Delete(scope, key string) (returnErr error) {
	if err := ValidateSlot(scope, key); err != nil {
		return err
	}
	itemsRoot, err := v.openItems(false)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer func() {
		returnErr = errors.Join(returnErr, wrapStoreError("store: close items directory", itemsRoot.Close()))
	}()
	name := slotName(scope, key)
	if _, err := inspectPrivateRegularFile(itemsRoot, name); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return fmt.Errorf("store: inspect item before delete: %w", err)
	}
	if err := itemsRoot.Remove(name); err != nil {
		return fmt.Errorf("store: delete item: %w", err)
	}
	if err := syncRoot(itemsRoot); err != nil {
		return fmt.Errorf("store: sync items directory: %w", err)
	}
	return nil
}

func openPrivateDirectory(path, label string) (*os.Root, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("store: inspect %s: %w", label, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("store: %s is not a directory", label)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("store: %s permissions are %#o; remove group and other access", label, info.Mode().Perm())
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", label, err)
	}
	openedInfo, err := root.Stat(".")
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf("store: inspect opened %s: %w", label, err),
			wrapStoreError("store: close "+label, root.Close()),
		)
	}
	if !os.SameFile(info, openedInfo) {
		return nil, errors.Join(
			fmt.Errorf("store: %s changed while it was opened", label),
			wrapStoreError("store: close "+label, root.Close()),
		)
	}
	return root, nil
}

func ensurePrivateDirectory(path, label string) (*os.Root, error) {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return nil, fmt.Errorf("store: create %s: %w", label, err)
	}
	return openPrivateDirectory(path, label)
}

func (v *Vault) openItems(create bool) (result *os.Root, returnErr error) {
	var vaultRoot *os.Root
	var err error
	if create {
		vaultRoot, err = ensurePrivateDirectory(v.dir, "directory")
	} else {
		vaultRoot, err = openPrivateDirectory(v.dir, "directory")
	}
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := vaultRoot.Close(); err != nil {
			returnErr = errors.Join(returnErr, fmt.Errorf("store: close directory: %w", err))
			if result != nil {
				returnErr = errors.Join(returnErr, wrapStoreError("store: close items directory", result.Close()))
				result = nil
			}
		}
	}()
	if create {
		if err := vaultRoot.Mkdir("items", 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("store: create items directory: %w", err)
		}
	}
	info, err := vaultRoot.Lstat("items")
	if err != nil {
		return nil, fmt.Errorf("store: inspect items directory: %w", err)
	}
	if !info.IsDir() {
		return nil, errors.New("store: items path is not a directory")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("store: items directory permissions are %#o; remove group and other access", info.Mode().Perm())
	}
	itemsRoot, err := vaultRoot.OpenRoot("items")
	if err != nil {
		return nil, fmt.Errorf("store: open items directory: %w", err)
	}
	openedInfo, err := itemsRoot.Stat(".")
	if err != nil {
		return nil, errors.Join(
			fmt.Errorf("store: inspect opened items directory: %w", err),
			wrapStoreError("store: close items directory", itemsRoot.Close()),
		)
	}
	if !os.SameFile(info, openedInfo) {
		return nil, errors.Join(
			errors.New("store: items directory changed while it was opened"),
			wrapStoreError("store: close items directory", itemsRoot.Close()),
		)
	}
	return itemsRoot, nil
}

func inspectPrivateRegularFile(root *os.Root, name string) (os.FileInfo, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("item is not a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("item permissions are %#o; remove group and other access", info.Mode().Perm())
	}
	if info.Size() > maximumItemFileSize {
		return nil, errors.New("item exceeds its size limit")
	}
	return info, nil
}

func readRegularFile(root *os.Root, name string) (result []byte, returnErr error) {
	info, err := inspectPrivateRegularFile(root, name)
	if err != nil {
		return nil, err
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() {
		returnErr = errors.Join(returnErr, wrapStoreError("close item", file.Close()))
	}()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, openedInfo) {
		return nil, errors.New("item changed while it was opened")
	}
	raw, err := io.ReadAll(io.LimitReader(file, maximumItemFileSize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maximumItemFileSize {
		return nil, errors.New("item exceeds its size limit")
	}
	return raw, nil
}

func createTemporaryItem(root *os.Root) (*os.File, string, error) {
	for range 100 {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return nil, "", err
		}
		name := ".nvault-item-" + hex.EncodeToString(random[:])
		file, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			return file, name, nil
		}
		if !errors.Is(err, os.ErrExist) {
			return nil, "", err
		}
	}
	return nil, "", errors.New("could not allocate a unique temporary item")
}

func syncRoot(root *os.Root) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	syncErr := directory.Sync()
	closeErr := directory.Close()
	return errors.Join(
		wrapStoreError("sync directory", syncErr),
		wrapStoreError("close directory", closeErr),
	)
}

func wrapStoreError(operation string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%s: %w", operation, err)
}
