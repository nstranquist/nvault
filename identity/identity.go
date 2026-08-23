// Package identity encodes passphrase-protected nvault identity files.
package identity

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/nstranquist/nvault/crypto"
	"github.com/nstranquist/nvault/internal/strictjson"
	"golang.org/x/crypto/argon2"
)

const (
	FormatV1                 = "nvault.identity.v1"
	MinimumPassphrase        = 12
	MaximumPassphrase        = 1024
	argonTime         uint32 = 2
	argonMemory       uint32 = 19 * 1024
	argonThreads      uint8  = 1
	keyBytes                 = 32
)

type KDF struct {
	Name      string `json:"name"`
	Time      uint32 `json:"time"`
	MemoryKiB uint32 `json:"memory_kib"`
	Threads   uint8  `json:"threads"`
	Salt      string `json:"salt"`
}

type Cipher struct {
	Name       string `json:"name"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type File struct {
	Format    string `json:"format"`
	PublicKey string `json:"public_key"`
	KDF       KDF    `json:"kdf"`
	Cipher    Cipher `json:"cipher"`
}

func validatePassphrase(passphrase []byte) error {
	if len(passphrase) < MinimumPassphrase || len(passphrase) > MaximumPassphrase {
		return fmt.Errorf("identity: passphrase must contain between %d and %d bytes", MinimumPassphrase, MaximumPassphrase)
	}
	return nil
}

func aad(publicKey string) []byte {
	return []byte(fmt.Sprintf("%s:%s:argon2id:%d:%d:%d", FormatV1, publicKey, argonTime, argonMemory, argonThreads))
}

// Wrap protects an identity private key with Argon2id and AES-256-GCM.
func Wrap(value crypto.Identity, passphrase []byte) ([]byte, error) {
	if err := validatePassphrase(passphrase); err != nil {
		return nil, err
	}
	if value.Public == (crypto.PublicKey{}) {
		return nil, errors.New("identity: identity is required")
	}
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("identity: generate salt: %w", err)
	}
	key := argon2.IDKey(passphrase, salt, argonTime, argonMemory, argonThreads, keyBytes)
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("identity: initialize cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("identity: initialize AEAD: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("identity: generate nonce: %w", err)
	}
	privateKey := value.Private()
	defer clear(privateKey)
	publicKey := value.Public.String()
	ciphertext := aead.Seal(nil, nonce, privateKey, aad(publicKey))
	record := File{
		Format:    FormatV1,
		PublicKey: publicKey,
		KDF: KDF{
			Name:      "argon2id",
			Time:      argonTime,
			MemoryKiB: argonMemory,
			Threads:   argonThreads,
			Salt:      base64.StdEncoding.EncodeToString(salt),
		},
		Cipher: Cipher{
			Name:       "AES-256-GCM",
			Nonce:      base64.StdEncoding.EncodeToString(nonce),
			Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		},
	}
	raw, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("identity: encode: %w", err)
	}
	return append(raw, '\n'), nil
}

func decodeBase64(value, field string, expected int) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil || base64.StdEncoding.EncodeToString(decoded) != value {
		return nil, fmt.Errorf("identity: %s is not canonical base64", field)
	}
	if len(decoded) != expected {
		return nil, fmt.Errorf("identity: %s must contain %d bytes", field, expected)
	}
	return decoded, nil
}

// Unwrap opens and authenticates a protected identity file.
func Unwrap(raw, passphrase []byte) (crypto.Identity, error) {
	if len(raw) > 16<<10 {
		return crypto.Identity{}, errors.New("identity: file exceeds 16384 bytes")
	}
	if len(passphrase) == 0 || len(passphrase) > MaximumPassphrase {
		return crypto.Identity{}, errors.New("identity: passphrase is required")
	}
	if err := strictjson.Check(raw, 16); err != nil {
		return crypto.Identity{}, fmt.Errorf("identity: invalid JSON: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var record File
	if err := decoder.Decode(&record); err != nil {
		return crypto.Identity{}, fmt.Errorf("identity: decode: %w", err)
	}
	var trailing unknownJSON
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return crypto.Identity{}, errors.New("identity: file contains trailing JSON data")
	}
	if record.Format != FormatV1 || record.KDF.Name != "argon2id" || record.KDF.Time != argonTime || record.KDF.MemoryKiB != argonMemory || record.KDF.Threads != argonThreads || record.Cipher.Name != "AES-256-GCM" {
		return crypto.Identity{}, errors.New("identity: unsupported identity format or parameters")
	}
	publicKey, err := crypto.ParsePublicKey(record.PublicKey)
	if err != nil {
		return crypto.Identity{}, fmt.Errorf("identity: public key: %w", err)
	}
	salt, err := decodeBase64(record.KDF.Salt, "salt", 16)
	if err != nil {
		return crypto.Identity{}, err
	}
	nonce, err := decodeBase64(record.Cipher.Nonce, "nonce", 12)
	if err != nil {
		return crypto.Identity{}, err
	}
	ciphertext, err := decodeBase64(record.Cipher.Ciphertext, "ciphertext", 48)
	if err != nil {
		return crypto.Identity{}, err
	}
	key := argon2.IDKey(passphrase, salt, argonTime, argonMemory, argonThreads, keyBytes)
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return crypto.Identity{}, fmt.Errorf("identity: initialize cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return crypto.Identity{}, fmt.Errorf("identity: initialize AEAD: %w", err)
	}
	privateKey, err := aead.Open(nil, nonce, ciphertext, aad(record.PublicKey))
	if err != nil {
		return crypto.Identity{}, errors.New("identity: could not unlock; check the passphrase and file")
	}
	defer clear(privateKey)
	value, err := crypto.IdentityFromPrivate(privateKey)
	if err != nil {
		return crypto.Identity{}, fmt.Errorf("identity: private key: %w", err)
	}
	if subtle.ConstantTimeCompare(value.Public[:], publicKey[:]) != 1 {
		return crypto.Identity{}, errors.New("identity: public key does not match the private key")
	}
	return value, nil
}

type unknownJSON any
