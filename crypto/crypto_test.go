package crypto

import (
	"bytes"
	"errors"
	"testing"
)

func mustIdentity(t *testing.T) Identity {
	t.Helper()
	id, err := GenerateIdentity()
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	return id
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	alice := mustIdentity(t)
	plaintext := []byte("super-secret-value")
	env, err := Encrypt(plaintext, []Recipient{alice.Recipient("alice")}, "org/proj/dev/DB_URL")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if env.Version != FormatV1 || env.Alg != AlgV1 {
		t.Fatalf("envelope header = %s/%s", env.Version, env.Alg)
	}
	if bytes.Contains(env.Ciphertext, plaintext) {
		t.Fatalf("ciphertext contains plaintext (not encrypted)")
	}
	got, err := Decrypt(env, alice)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("Decrypt = %q want %q", got, plaintext)
	}
}

func TestMultiRecipientEachCanDecrypt(t *testing.T) {
	alice, bob, carol := mustIdentity(t), mustIdentity(t), mustIdentity(t)
	recipients := []Recipient{alice.Recipient("alice"), bob.Recipient("bob"), carol.Recipient("carol")}
	env, err := Encrypt([]byte("shared"), recipients, "")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if len(env.Stanzas) != 3 {
		t.Fatalf("want 3 stanzas, got %d", len(env.Stanzas))
	}
	for _, id := range []Identity{alice, bob, carol} {
		got, err := Decrypt(env, id)
		if err != nil {
			t.Fatalf("Decrypt for recipient: %v", err)
		}
		if string(got) != "shared" {
			t.Fatalf("got %q", got)
		}
	}
}

func TestNonRecipientCannotDecrypt(t *testing.T) {
	alice := mustIdentity(t)
	mallory := mustIdentity(t)
	env, err := Encrypt([]byte("secret"), []Recipient{alice.Recipient("alice")}, "")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := Decrypt(env, mallory); !errors.Is(err, ErrNoMatchingRecipient) {
		t.Fatalf("non-recipient Decrypt err = %v, want ErrNoMatchingRecipient", err)
	}
}

func TestTamperDetection(t *testing.T) {
	alice := mustIdentity(t)
	env, err := Encrypt([]byte("integrity-matters"), []Recipient{alice.Recipient("alice")}, "")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	env.Ciphertext[0] ^= 0x01
	if _, err := Decrypt(env, alice); !errors.Is(err, ErrTampered) {
		t.Fatalf("tampered Decrypt err = %v, want ErrTampered", err)
	}
}

func TestAADBinding(t *testing.T) {
	alice := mustIdentity(t)
	env, err := Encrypt([]byte("located"), []Recipient{alice.Recipient("alice")}, "org/proj/prod/KEY")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	env.AAD = "org/proj/dev/KEY"
	if _, err := Decrypt(env, alice); !errors.Is(err, ErrTampered) {
		t.Fatalf("relocated envelope Decrypt err = %v, want ErrTampered (AAD must bind)", err)
	}
}

func TestRewrapRotation(t *testing.T) {
	alice, bob, carol := mustIdentity(t), mustIdentity(t), mustIdentity(t)
	env, err := Encrypt([]byte("rotate-me"), []Recipient{alice.Recipient("alice"), bob.Recipient("bob")}, "")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	rewrapped, err := Rewrap(env, alice, []Recipient{alice.Recipient("alice"), carol.Recipient("carol")})
	if err != nil {
		t.Fatalf("Rewrap: %v", err)
	}
	if !bytes.Equal(rewrapped.Ciphertext, env.Ciphertext) {
		t.Fatalf("rewrap changed ciphertext body")
	}
	if got, err := Decrypt(rewrapped, carol); err != nil || string(got) != "rotate-me" {
		t.Fatalf("carol Decrypt after rewrap: got=%q err=%v", got, err)
	}
	if _, err := Decrypt(rewrapped, bob); !errors.Is(err, ErrNoMatchingRecipient) {
		t.Fatalf("removed member bob err = %v, want ErrNoMatchingRecipient", err)
	}
}

func TestRecoveryKeyIsJustARecipient(t *testing.T) {
	member := mustIdentity(t)
	recovery := mustIdentity(t)
	env, err := Encrypt([]byte("breakglass"), []Recipient{
		member.Recipient("member"),
		recovery.Recipient("recovery"),
	}, "")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := Decrypt(env, recovery)
	if err != nil || string(got) != "breakglass" {
		t.Fatalf("recovery Decrypt: got=%q err=%v", got, err)
	}
}

func TestIdentityFromPrivateRoundTrip(t *testing.T) {
	orig := mustIdentity(t)
	restored, err := IdentityFromPrivate(orig.Private())
	if err != nil {
		t.Fatalf("IdentityFromPrivate: %v", err)
	}
	if restored.Public != orig.Public {
		t.Fatalf("derived public key mismatch:\n  orig=%s\n  rest=%s", orig.Public, restored.Public)
	}
	env, err := Encrypt([]byte("x"), []Recipient{orig.Recipient("me")}, "")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if got, err := Decrypt(env, restored); err != nil || string(got) != "x" {
		t.Fatalf("restored identity Decrypt: got=%q err=%v", got, err)
	}
}

func TestPublicKeyEncodeParseRoundTrip(t *testing.T) {
	id := mustIdentity(t)
	s := id.Public.String()
	parsed, err := ParsePublicKey(s)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	if parsed != id.Public {
		t.Fatalf("public key round-trip mismatch")
	}
	if _, err := ParsePublicKey("garbage"); err == nil {
		t.Fatalf("ParsePublicKey(garbage) should fail")
	}
	if id.Public.Fingerprint() == "" {
		t.Fatalf("fingerprint empty")
	}
}

func TestEnvelopeJSONRoundTrip(t *testing.T) {
	alice := mustIdentity(t)
	env, err := Encrypt([]byte("json-me"), []Recipient{alice.Recipient("alice")}, "aad-here")
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	b, err := Marshal(env)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	plain, err := Decrypt(got, alice)
	if err != nil || string(plain) != "json-me" {
		t.Fatalf("decrypt after JSON round-trip: got=%q err=%v", plain, err)
	}
}

func TestEncryptRequiresRecipient(t *testing.T) {
	if _, err := Encrypt([]byte("x"), nil, ""); !errors.Is(err, ErrNoRecipients) {
		t.Fatalf("Encrypt with no recipients err = %v, want ErrNoRecipients", err)
	}
}

func TestUnsupportedFormatRejected(t *testing.T) {
	alice := mustIdentity(t)
	env, _ := Encrypt([]byte("x"), []Recipient{alice.Recipient("a")}, "")
	env.Version = "nvault.enc.v99"
	if _, err := Decrypt(env, alice); !errors.Is(err, ErrUnsupportedFormat) {
		t.Fatalf("future-version Decrypt err = %v, want ErrUnsupportedFormat", err)
	}
}
