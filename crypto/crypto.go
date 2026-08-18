// Package crypto implements the zero-knowledge envelope encryption that backs
// nvault's remote tier. The server only ever stores Envelopes (ciphertext +
// per-recipient wrapped data keys); it never holds a private key and cannot
// recover plaintext.
//
// Model (age-style recipient encryption):
//
//   - Each member has an X25519 Identity (keypair). The private half stays
//     client-side (in the OS Keychain locally); only the public half is shared.
//   - Each secret is encrypted under a fresh random 256-bit data key (DEK) with
//     XChaCha20-Poly1305 (24-byte nonce, AEAD).
//   - The DEK is wrapped to every authorized recipient's public key using a NaCl
//     sealed box (anonymous sender — an ephemeral keypair per wrap). Any holder
//     of a recipient private key can unwrap the DEK and decrypt; nobody else can.
//   - A recovery key is simply an additional recipient whose private key is
//     escrowed/printed at org-init time.
//   - Rotation = Rewrap: decrypt the DEK with one identity, re-seal it to a new
//     recipient set. The ciphertext body is untouched, so rotation is cheap.
//
// Wire format is versioned (FormatV1 = "nvault.enc.v1") and JSON-serializable so
// it round-trips cleanly through the Convex document store.
package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)

const (
	// FormatV1 is the versioned envelope tag. Bump only on a breaking change to
	// the wire format; readers must reject unknown versions.
	FormatV1 = "nvault.enc.v1"
	// AlgV1 names the primitive suite for FormatV1.
	AlgV1 = "x25519-xchacha20poly1305"

	keySize   = 32 // X25519 / DEK
	nonceSize = chacha20poly1305.NonceSizeX
)

var (
	// ErrNoMatchingRecipient means the supplied identity is not among the
	// envelope's recipients (or the wrapped key was tampered with).
	ErrNoMatchingRecipient = errors.New("crypto: no recipient stanza decrypts with this identity")
	// ErrUnsupportedFormat means the envelope version/alg is not understood.
	ErrUnsupportedFormat = errors.New("crypto: unsupported envelope format")
	// ErrTampered means the AEAD tag failed — ciphertext or AAD was modified.
	ErrTampered = errors.New("crypto: authentication failed (tampered ciphertext)")
	// ErrNoRecipients means Encrypt was called with an empty recipient set.
	ErrNoRecipients = errors.New("crypto: at least one recipient is required")
)

// Identity is an X25519 keypair. The private key is secret and stays local.
type Identity struct {
	Public  PublicKey
	private [keySize]byte
}

// PublicKey is a 32-byte X25519 public key.
type PublicKey [keySize]byte

// GenerateIdentity creates a fresh random keypair.
func GenerateIdentity() (Identity, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return Identity{}, fmt.Errorf("crypto: generate identity: %w", err)
	}
	var id Identity
	id.Public = PublicKey(*pub)
	id.private = *priv
	return id, nil
}

// IdentityFromPrivate reconstructs an Identity from a stored private key,
// deriving the matching public key.
func IdentityFromPrivate(private []byte) (Identity, error) {
	if len(private) != keySize {
		return Identity{}, fmt.Errorf("crypto: private key must be %d bytes, got %d", keySize, len(private))
	}
	var priv [keySize]byte
	copy(priv[:], private)
	// Derive the public key exactly as nacl/box does: X25519 of the private
	// scalar against the curve basepoint.
	pubBytes, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return Identity{}, fmt.Errorf("crypto: derive public key: %w", err)
	}
	var id Identity
	copy(id.Public[:], pubBytes)
	id.private = priv
	return id, nil
}

// Private returns a copy of the raw private key bytes (for secure storage).
func (id Identity) Private() []byte {
	out := make([]byte, keySize)
	copy(out, id.private[:])
	return out
}

// Recipient is a labeled public key that an envelope can be sealed to.
type Recipient struct {
	ID        string    `json:"id"`
	PublicKey PublicKey `json:"public_key"`
}

// Recipient returns the Recipient view of an identity, using the given label.
func (id Identity) Recipient(label string) Recipient {
	return Recipient{ID: label, PublicKey: id.Public}
}

// Fingerprint is a short, human-comparable digest of a public key.
func (p PublicKey) Fingerprint() string {
	sum := sha256.Sum256(p[:])
	return "SHA256:" + base64.RawStdEncoding.EncodeToString(sum[:])[:16]
}

// String encodes a public key for sharing (e.g. config files, CLI output).
func (p PublicKey) String() string {
	return "nvpub_" + base64.RawURLEncoding.EncodeToString(p[:])
}

// MarshalJSON / UnmarshalJSON keep PublicKey portable as the String() form.
func (p PublicKey) MarshalJSON() ([]byte, error) { return json.Marshal(p.String()) }

func (p *PublicKey) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	pk, err := ParsePublicKey(s)
	if err != nil {
		return err
	}
	*p = pk
	return nil
}

// ParsePublicKey decodes the String() encoding back into a PublicKey.
func ParsePublicKey(s string) (PublicKey, error) {
	const prefix = "nvpub_"
	if len(s) <= len(prefix) || s[:len(prefix)] != prefix {
		return PublicKey{}, fmt.Errorf("crypto: public key must start with %q", prefix)
	}
	raw, err := base64.RawURLEncoding.DecodeString(s[len(prefix):])
	if err != nil {
		return PublicKey{}, fmt.Errorf("crypto: decode public key: %w", err)
	}
	if len(raw) != keySize {
		return PublicKey{}, fmt.Errorf("crypto: public key must be %d bytes, got %d", keySize, len(raw))
	}
	var pk PublicKey
	copy(pk[:], raw)
	return pk, nil
}

// Stanza is one recipient's wrapped copy of the data key.
type Stanza struct {
	RecipientID string `json:"recipient_id"`
	// WrappedKey is a NaCl sealed box of the DEK to the recipient's public key.
	WrappedKey []byte `json:"wrapped_key"`
}

// Envelope is the serializable encrypted payload.
type Envelope struct {
	Version    string   `json:"v"`
	Alg        string   `json:"alg"`
	Nonce      []byte   `json:"nonce"`
	Ciphertext []byte   `json:"ciphertext"`
	Stanzas    []Stanza `json:"recipients"`
	// AAD is optional associated data bound into the AEAD (e.g. "org/proj/env/KEY")
	// so an envelope cannot be silently relocated to a different logical slot.
	AAD string `json:"aad,omitempty"`
}

// Encrypt seals plaintext to every recipient. aad (may be "") is authenticated
// but not encrypted; the same aad must be supplied at Decrypt.
func Encrypt(plaintext []byte, recipients []Recipient, aad string) (*Envelope, error) {
	if len(recipients) == 0 {
		return nil, ErrNoRecipients
	}
	dek := make([]byte, keySize)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("crypto: read random dek: %w", err)
	}
	aead, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return nil, fmt.Errorf("crypto: init aead: %w", err)
	}
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("crypto: read random nonce: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, []byte(aad))

	stanzas := make([]Stanza, 0, len(recipients))
	for _, r := range recipients {
		recipientPub := [keySize]byte(r.PublicKey)
		wrapped, err := box.SealAnonymous(nil, dek, &recipientPub, rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("crypto: wrap dek for %q: %w", r.ID, err)
		}
		stanzas = append(stanzas, Stanza{RecipientID: r.ID, WrappedKey: wrapped})
	}
	// Deterministic stanza order keeps envelopes stable for tests/diffing.
	sort.Slice(stanzas, func(i, j int) bool { return stanzas[i].RecipientID < stanzas[j].RecipientID })

	return &Envelope{
		Version:    FormatV1,
		Alg:        AlgV1,
		Nonce:      nonce,
		Ciphertext: ciphertext,
		Stanzas:    stanzas,
		AAD:        aad,
	}, nil
}

// Decrypt opens an envelope with the given identity. It tries every stanza; the
// one sealed to this identity's public key unwraps the DEK.
func Decrypt(env *Envelope, id Identity) ([]byte, error) {
	if env.Version != FormatV1 || env.Alg != AlgV1 {
		return nil, fmt.Errorf("%w: %s/%s", ErrUnsupportedFormat, env.Version, env.Alg)
	}
	pub := [keySize]byte(id.Public)
	priv := id.private
	for _, st := range env.Stanzas {
		dek, ok := box.OpenAnonymous(nil, st.WrappedKey, &pub, &priv)
		if !ok {
			continue
		}
		aead, err := chacha20poly1305.NewX(dek)
		if err != nil {
			return nil, fmt.Errorf("crypto: init aead: %w", err)
		}
		plaintext, err := aead.Open(nil, env.Nonce, env.Ciphertext, []byte(env.AAD))
		if err != nil {
			return nil, ErrTampered
		}
		return plaintext, nil
	}
	return nil, ErrNoMatchingRecipient
}

// Rewrap re-seals an existing envelope to a new recipient set without changing
// the encrypted body. The caller must hold an identity that can currently
// decrypt (to recover the DEK). This is the rotation / membership-change path.
func Rewrap(env *Envelope, id Identity, newRecipients []Recipient) (*Envelope, error) {
	if env.Version != FormatV1 || env.Alg != AlgV1 {
		return nil, fmt.Errorf("%w: %s/%s", ErrUnsupportedFormat, env.Version, env.Alg)
	}
	if len(newRecipients) == 0 {
		return nil, ErrNoRecipients
	}
	pub := [keySize]byte(id.Public)
	priv := id.private
	var dek []byte
	for _, st := range env.Stanzas {
		if d, ok := box.OpenAnonymous(nil, st.WrappedKey, &pub, &priv); ok {
			dek = d
			break
		}
	}
	if dek == nil {
		return nil, ErrNoMatchingRecipient
	}
	stanzas := make([]Stanza, 0, len(newRecipients))
	for _, r := range newRecipients {
		recipientPub := [keySize]byte(r.PublicKey)
		wrapped, err := box.SealAnonymous(nil, dek, &recipientPub, rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("crypto: rewrap dek for %q: %w", r.ID, err)
		}
		stanzas = append(stanzas, Stanza{RecipientID: r.ID, WrappedKey: wrapped})
	}
	sort.Slice(stanzas, func(i, j int) bool { return stanzas[i].RecipientID < stanzas[j].RecipientID })

	out := *env
	out.Stanzas = stanzas
	return &out, nil
}

// Marshal/Unmarshal are convenience wrappers for the JSON wire form.
func Marshal(env *Envelope) ([]byte, error) { return json.Marshal(env) }

func Unmarshal(b []byte) (*Envelope, error) {
	var env Envelope
	if err := json.Unmarshal(b, &env); err != nil {
		return nil, fmt.Errorf("crypto: decode envelope: %w", err)
	}
	return &env, nil
}
