// Package crypto implements the zero-knowledge envelope encryption that backs
// nvault's remote tier. The server only ever stores Envelopes (ciphertext +
// per-recipient wrapped data keys); it never holds a private key and cannot
// recover plaintext.
//
// Model (age-style recipient encryption):
//
//   - Each member has an X25519 Identity (keypair). The private half stays
//     client-side in a passphrase-protected identity file; only the public half
//     is shared.
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
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"

	"github.com/nstranquist/nvault/internal/strictjson"
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

	// MaxPlaintextSize bounds one envelope body. nvault is a secrets store, not
	// a general-purpose encrypted object store.
	MaxPlaintextSize = 16 << 20
	// MaxRecipients bounds work performed against an untrusted envelope.
	MaxRecipients = 1024
	// MaxAADSize bounds the logical slot name authenticated by an envelope.
	MaxAADSize = 4096
	// MaxRecipientIDSize bounds one human-readable recipient label.
	MaxRecipientIDSize = 256
	// MaxEnvelopeJSONSize bounds decoding work for the JSON wire form.
	MaxEnvelopeJSONSize = 32 << 20

	keySize        = 32 // X25519 / DEK
	nonceSize      = chacha20poly1305.NonceSizeX
	wrappedKeySize = keySize + keySize + box.Overhead
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
	// ErrAADMismatch means an envelope does not belong to the expected logical
	// slot. Callers must supply the slot they looked up, not trust env.AAD.
	ErrAADMismatch = errors.New("crypto: envelope associated data does not match expected slot")
	// ErrInvalidEnvelope means untrusted envelope data is malformed or exceeds
	// a resource limit.
	ErrInvalidEnvelope = errors.New("crypto: invalid envelope")
	// ErrInvalidRecipient means a recipient set is malformed or ambiguous.
	ErrInvalidRecipient = errors.New("crypto: invalid recipient")
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
	var nonzero byte
	for _, b := range private {
		nonzero |= b
	}
	if nonzero == 0 {
		return Identity{}, errors.New("crypto: private key cannot be all zeroes")
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
	if pk.String() != s {
		return PublicKey{}, errors.New("crypto: public key is not canonically encoded")
	}
	var nonzero byte
	for _, b := range pk {
		nonzero |= b
	}
	if nonzero == 0 {
		return PublicKey{}, errors.New("crypto: public key cannot be all zeroes")
	}
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
	if len(plaintext) > MaxPlaintextSize {
		return nil, fmt.Errorf("%w: plaintext is %d bytes; maximum is %d", ErrInvalidEnvelope, len(plaintext), MaxPlaintextSize)
	}
	if len(aad) > MaxAADSize {
		return nil, fmt.Errorf("%w: associated data is %d bytes; maximum is %d", ErrInvalidEnvelope, len(aad), MaxAADSize)
	}
	if err := validateRecipients(recipients); err != nil {
		return nil, err
	}
	dek := make([]byte, keySize)
	defer clear(dek)
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

// Decrypt opens an envelope for expectedAAD with the given identity. The
// expected value must come from the logical slot the caller requested. This
// prevents an untrusted store from moving a valid envelope to another slot.
func Decrypt(env *Envelope, id Identity, expectedAAD string) ([]byte, error) {
	if err := ValidateEnvelope(env); err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(env.AAD), []byte(expectedAAD)) != 1 {
		return nil, ErrAADMismatch
	}
	pub := [keySize]byte(id.Public)
	priv := id.private
	for _, st := range env.Stanzas {
		dek, ok := box.OpenAnonymous(nil, st.WrappedKey, &pub, &priv)
		if !ok {
			continue
		}
		defer clear(dek)
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
func Rewrap(env *Envelope, id Identity, expectedAAD string, newRecipients []Recipient) (*Envelope, error) {
	if err := ValidateEnvelope(env); err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(env.AAD), []byte(expectedAAD)) != 1 {
		return nil, ErrAADMismatch
	}
	if err := validateRecipients(newRecipients); err != nil {
		return nil, err
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
	defer clear(dek)
	// Authenticate the unchanged body before publishing new recipient stanzas.
	// A rewrap must not preserve a corrupted ciphertext.
	aead, err := chacha20poly1305.NewX(dek)
	if err != nil {
		return nil, fmt.Errorf("crypto: init aead: %w", err)
	}
	verifiedPlaintext, err := aead.Open(nil, env.Nonce, env.Ciphertext, []byte(env.AAD))
	if err != nil {
		return nil, ErrTampered
	}
	clear(verifiedPlaintext)
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

// ValidateEnvelope validates untrusted wire data before any crypto primitive is
// called. It prevents panics and bounds CPU and memory work.
func ValidateEnvelope(env *Envelope) error {
	if env == nil {
		return fmt.Errorf("%w: envelope is nil", ErrInvalidEnvelope)
	}
	if env.Version != FormatV1 || env.Alg != AlgV1 {
		return fmt.Errorf("%w: %s/%s", ErrUnsupportedFormat, env.Version, env.Alg)
	}
	if len(env.Nonce) != nonceSize {
		return fmt.Errorf("%w: nonce must be %d bytes, got %d", ErrInvalidEnvelope, nonceSize, len(env.Nonce))
	}
	if len(env.Ciphertext) < chacha20poly1305.Overhead || len(env.Ciphertext) > MaxPlaintextSize+chacha20poly1305.Overhead {
		return fmt.Errorf("%w: ciphertext length %d is outside [%d,%d]", ErrInvalidEnvelope, len(env.Ciphertext), chacha20poly1305.Overhead, MaxPlaintextSize+chacha20poly1305.Overhead)
	}
	if len(env.AAD) > MaxAADSize {
		return fmt.Errorf("%w: associated data is %d bytes; maximum is %d", ErrInvalidEnvelope, len(env.AAD), MaxAADSize)
	}
	if len(env.Stanzas) == 0 || len(env.Stanzas) > MaxRecipients {
		return fmt.Errorf("%w: recipient count %d is outside [1,%d]", ErrInvalidEnvelope, len(env.Stanzas), MaxRecipients)
	}
	seen := make(map[string]struct{}, len(env.Stanzas))
	for i, st := range env.Stanzas {
		if st.RecipientID == "" || len(st.RecipientID) > MaxRecipientIDSize {
			return fmt.Errorf("%w: recipient %d id length %d is outside [1,%d]", ErrInvalidEnvelope, i, len(st.RecipientID), MaxRecipientIDSize)
		}
		if _, ok := seen[st.RecipientID]; ok {
			return fmt.Errorf("%w: duplicate recipient id %q", ErrInvalidEnvelope, st.RecipientID)
		}
		seen[st.RecipientID] = struct{}{}
		if len(st.WrappedKey) != wrappedKeySize {
			return fmt.Errorf("%w: recipient %q wrapped key must be %d bytes, got %d", ErrInvalidEnvelope, st.RecipientID, wrappedKeySize, len(st.WrappedKey))
		}
	}
	return nil
}

func validateRecipients(recipients []Recipient) error {
	if len(recipients) == 0 {
		return ErrNoRecipients
	}
	if len(recipients) > MaxRecipients {
		return fmt.Errorf("%w: recipient count %d exceeds %d", ErrInvalidRecipient, len(recipients), MaxRecipients)
	}
	seen := make(map[string]struct{}, len(recipients))
	for i, recipient := range recipients {
		if recipient.ID == "" || len(recipient.ID) > MaxRecipientIDSize {
			return fmt.Errorf("%w: recipient %d id length %d is outside [1,%d]", ErrInvalidRecipient, i, len(recipient.ID), MaxRecipientIDSize)
		}
		if _, ok := seen[recipient.ID]; ok {
			return fmt.Errorf("%w: duplicate recipient id %q", ErrInvalidRecipient, recipient.ID)
		}
		seen[recipient.ID] = struct{}{}
		var nonzero byte
		for _, b := range recipient.PublicKey {
			nonzero |= b
		}
		if nonzero == 0 {
			return fmt.Errorf("%w: recipient %q has an all-zero public key", ErrInvalidRecipient, recipient.ID)
		}
	}
	return nil
}

// Marshal/Unmarshal are validated convenience wrappers for the JSON wire form.
func Marshal(env *Envelope) ([]byte, error) {
	if err := ValidateEnvelope(env); err != nil {
		return nil, err
	}
	return json.Marshal(env)
}

func Unmarshal(b []byte) (*Envelope, error) {
	if len(b) > MaxEnvelopeJSONSize {
		return nil, fmt.Errorf("%w: envelope JSON is %d bytes; maximum is %d", ErrInvalidEnvelope, len(b), MaxEnvelopeJSONSize)
	}
	if err := strictjson.Check(b, 16); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}
	var env Envelope
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&env); err != nil {
		return nil, fmt.Errorf("crypto: decode envelope: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: envelope contains trailing JSON data", ErrInvalidEnvelope)
	}
	if err := ValidateEnvelope(&env); err != nil {
		return nil, err
	}
	return &env, nil
}
